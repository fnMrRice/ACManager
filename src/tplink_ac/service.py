"""UDP transport worker shared by the Windows application and future procd host."""
import json
import ipaddress
import re
import os
import queue
import select
import socket
import struct
import threading
import time
from collections import deque
from concurrent.futures import Future
from .controller import Controller
from .protocol import Reassembler, ProtocolError, fragment, header, parse_tlvs
from .dtls import Library, Credentials, Session, DTLSError, PREAMBLE

DEFAULTS = {'enabled':False, 'ac_ip':'192.168.1.2', 'listen_ip':'0.0.0.0',
            'control_port':5246, 'data_port':5247, 'allowed_ips':[],
            'name':'Windows TP-LINK AC', 'dtls':True, 'allow_plaintext':False,
            'cert':'', 'key':'', 'ca':'', 'verify_peer':True,'discovery_only':False,
            'legacy_dtls':False,'dtls_backend':'auto', 'auto_adopt':False,
            'adopt_subnets':[], 'ap_metadata':{}}

def validate_config(value):
    if not isinstance(value,dict): raise ValueError('连接设置必须是对象')
    cfg = DEFAULTS | {k:v for k,v in value.items() if k in DEFAULTS}
    for field in ('name','cert','key','ca'):
        if not isinstance(cfg[field],str) or '\0' in cfg[field] or len(cfg[field])>2048:
            raise ValueError('无效文本字段：'+field)
    for name in ('ac_ip','listen_ip'):
        try: socket.inet_pton(socket.AF_INET,cfg[name])
        except (ValueError,OSError,TypeError): raise ValueError('IPv4 地址无效: '+name)
    if cfg['ac_ip'] in ('0.0.0.0','255.255.255.255'):
        raise ValueError('AC 地址必须是本机网卡的具体 IPv4 地址')
    for field in ('control_port','data_port'):
        cfg[field] = int(cfg[field])
        if not 1 <= cfg[field] <= 65535: raise ValueError('端口必须为 1..65535')
    if cfg['control_port'] == cfg['data_port']: raise ValueError('控制和数据端口不能相同')
    if not isinstance(cfg['allowed_ips'],list) or len(cfg['allowed_ips']) > 64:
        raise ValueError('AP IP 列表应为最多 64 项的数组')
    for field in ('allowed_ips',):
        if not isinstance(cfg[field],list) or len(cfg[field])>256: raise ValueError('无效 AP 地址列表')
        for ip in cfg[field]: socket.inet_pton(socket.AF_INET,ip)
    if not isinstance(cfg['adopt_subnets'],list) or len(cfg['adopt_subnets'])>16: raise ValueError('无效接管网段')
    for net in cfg['adopt_subnets']:
        network=ipaddress.ip_network(net)
        if network.version!=4 or network.prefixlen<16: raise ValueError('接管网段需为 /16 至 /32 的 IPv4 网段')
    metadata=cfg['ap_metadata']
    if not isinstance(metadata,dict) or len(metadata)>256: raise ValueError('AP 配置条目过多')
    for mac,item in metadata.items():
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac) or not isinstance(item,dict): raise ValueError('无效 AP MAC')
        if set(item)-{'name','remark','adoption'}: raise ValueError('无效 AP 配置字段')
        if item.get('adoption','default') not in ('default','allow','block'): raise ValueError('无效接管策略')
        for key,limit in (('name',64),('remark',256)):
            value=item.get(key,'')
            if not isinstance(value,str) or len(value)>limit or any(ord(c)<32 for c in value): raise ValueError('无效 AP 名称或备注')
    for field in ('enabled','dtls','allow_plaintext','verify_peer','discovery_only','legacy_dtls','auto_adopt'):
        if not isinstance(cfg[field],bool): raise ValueError(field+' 必须是布尔值')
    if cfg['dtls_backend'] not in ('auto','openssl','gnutls'): raise ValueError('无效 DTLS 实现')
    if cfg['auto_adopt'] and not cfg['adopt_subnets']: raise ValueError('默认接管需要指定局域网网段')
    if cfg['enabled'] and not (cfg['allowed_ips'] or cfg['adopt_subnets'] or any(v.get('adoption')=='allow' for v in metadata.values())): raise ValueError('主动管理需要选择 AP 或设置默认接管网段')
    if cfg['enabled'] and not cfg['dtls'] and not cfg['allow_plaintext']:
        raise ValueError('请选择 DTLS，或明确启用明文兼容实验')
    return cfg

class Service:
    def __init__(self):
        self.lock,self.commands,self.stop_event = threading.RLock(),queue.Queue(32),threading.Event()
        self.thread,self.engine = None,None
        self.events = deque(maxlen=200)
        self.error,self.running = '',False
        self.credentials,self.secure,self.sockets = None,{},[]
        self.config = dict(DEFAULTS)
        self.fragment_id = 0
        self.blocked_stations = frozenset()
        self.balance_rules = {}

    def log(self, message):
        with self.lock:
            self.events.append({'time':time.strftime('%H:%M:%S'),'message':str(message)[:500]})

    def start(self, config):
        if self.thread and self.thread.is_alive(): raise ValueError('请先停止服务再修改连接设置')
        self.config = validate_config(config)
        self.error = ''
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run,daemon=True,name='capwap')
        ready = Future()
        self.ready = ready
        self.thread.start()
        return ready.result(timeout=8)

    def stop(self):
        self.stop_event.set()
        if self.thread and self.thread is not threading.current_thread(): self.thread.join(timeout=3)
        if self.thread and self.thread.is_alive(): raise RuntimeError('网络服务尚未停止')

    def action(self, ip, action, profile=None):
        if not self.running: raise ValueError('服务未启动')
        future = Future()
        self.commands.put_nowait((future,ip,action,profile))
        return future.result(timeout=5)

    def snapshot(self):
        with self.lock:
            status = self.engine.status() if self.engine else {'aps':[], 'experimental':True,'hardware_verified':False}
            return status | {'running':self.running,'error':self.error,'events':list(self.events)}

    def take_readback(self,ident):
        with self.lock:
            if not self.engine: return None
            item=self.engine.read_requests.get(ident,{})
            if 'result' not in item: return None
            self.engine.read_requests.pop(ident,None)
            return item['result']

    def update_policy(self,config):
        """Apply admission edits under the transport lock without restarting peers."""
        with self.lock:
            self.config=config
            if self.engine:
                self.engine.config=config
                for peer,ap in self.engine.peers.items():
                    if not self.engine.allowed(peer):
                        if ap.get('pending'):
                            p=ap['pending'];self.engine.record(ap,{'id':p['id'],'action':p['action'],'status':'cancelled'})
                        ap.update(state='observed',pending=None,cache={})
                for peer in list(self.secure):
                    if not self.engine.allowed(peer): self.secure.pop(peer)['session'].close()

    def update_station_policy(self,rules):
        with self.lock:
            self.blocked_stations=frozenset(rules)
            if self.engine:
                self.engine.blocked_stations=self.blocked_stations
                # Do not replay a cached acceptance after admission rules changed.
                for ap in self.engine.peers.values(): ap['cache'].clear()

    def update_balance(self,rules):
        from copy import deepcopy
        with self.lock:
            if self.balance_rules==rules:return
            self.balance_rules=deepcopy(rules)
            if self.engine:
                self.engine.balance.configure(rules)
                for ap in self.engine.peers.values():ap['cache'].clear()

    def _send(self, peer, packet, secure):
        self.fragment_id = (self.fragment_id+1) & 65535
        for part in fragment(packet,self.fragment_id):
            if secure:
                if peer not in self.secure: raise DTLSError('DTLS session no longer exists')
                # Captured TP-LINK JOIN retains type=1 inside the encrypted
                # CAPWAP header. Mirror only the established peer's framing.
                if self.secure[peer].get('inner_dtls_type'): part=b'\x01'+part[1:]
                self.secure[peer]['session'].send(part)
            else: self.sockets[0].sendto(part,peer)

    def _consume(self, peer, packet, secure):
        if secure and packet[:1]==b'\x01':
            if peer not in self.secure: raise DTLSError('DTLS session no longer exists')
            self.secure[peer]['inner_dtls_type'] = True
            packet=b'\0'+packet[1:]
        complete = self.reassembler.feed((peer,secure),packet)
        if complete:
            self.engine.receive(peer,complete,secure)

    def _data(self, peer, packet):
        if not self.engine.allowed(peer): return
        h = header(packet)
        if h.word != (2 << 19) | 8 or h.fragmented or len(packet) > 128:
            raise ProtocolError('只实现本地转发的数据通道保活，不支持集中转发')
        payload = packet[h.length:]
        if len(payload) < 2 or struct.unpack_from('!H',payload)[0] != len(payload):
            raise ProtocolError('invalid data keepalive length')
        fields = parse_tlvs(payload[2:])
        sid = [v for t,v in fields if t == 35]
        if len(sid) != 1 or len(sid[0]) != 16: raise ProtocolError('invalid data session ID')
        for control_peer,ap in self.engine.peers.items():
            if control_peer[0] == peer[0] and ap.get('session_id') == sid[0].hex() and ap['state'] in ('configured','run'):
                self.sockets[1].sendto(packet,peer)
                ap.update(state='run',last_seen=time.monotonic())
                return
        raise ProtocolError('data keepalive has no matching control session')

    def _run(self):
        self.reassembler = Reassembler()
        rates = {}
        try:
            self.cookie_gate = None
            self.session_class = Session
            if self.config['enabled'] and self.config['dtls'] and not self.config['discovery_only']:
                backend = self.config['dtls_backend']
                if backend=='auto': backend = 'openssl' if os.name=='nt' else 'gnutls'
                if backend=='gnutls':
                    from . import dtls_gnutls as transport
                    library = transport.Library()
                    credential_class,self.session_class = transport.Credentials,transport.Session
                    self.cookie_gate = transport.CookieGate(library)
                else:
                    library,credential_class = Library(),Credentials
                self.credentials = credential_class(library,self.config['cert'],self.config['key'],
                                               self.config['ca'],self.config['verify_peer'],legacy=self.config['legacy_dtls'])
                self.log('DTLS 实现：'+backend+('，已启用旧 AP 协议兼容' if self.config['legacy_dtls'] else ''))
            for port in (self.config['control_port'],self.config['data_port']):
                sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                self.sockets.append(sock)
                # No SO_REUSEADDR: do not silently share another AC's port.
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
                sock.bind((self.config['listen_ip'],port))
                sock.setblocking(False)
            with self.lock:
                self.engine = Controller(self.config,self._send)
                self.engine.blocked_stations=self.blocked_stations
                self.engine.balance.configure(self.balance_rules)
                self.running = True
            mode = '仅观察，不回复 AP'
            if self.config['enabled']: mode = '仅回复发现，不接管 AP' if self.config['discovery_only'] else '主动管理（实验）'
            self.log('CAPWAP 已启动：'+mode)
            self.ready.set_result({'running':True})
            while not self.stop_event.is_set():
                with self.lock:
                    while not self.commands.empty():
                        future,ip,action,profile = self.commands.get_nowait()
                        try: future.set_result(self.engine.operation(ip,action,profile))
                        except Exception as e: future.set_exception(e)
                    for sock in select.select(self.sockets,[],[],0.1)[0]:
                        packet,peer = sock.recvfrom(65535)
                        now = time.monotonic()
                        rates = {p:v for p,v in rates.items() if now-v[0]<1}
                        if peer[0] not in rates and len(rates)>=128: continue
                        start,count = rates.get(peer[0],(now,0))
                        rates[peer[0]] = (start,count+1)
                        if count >= 100: continue
                        try:
                            if sock is self.sockets[1]: self._data(peer,packet)
                            elif packet.startswith(PREAMBLE):
                                if not self.engine.allowed(peer) or not self.credentials:
                                    self.log(peer[0]+' 请求 DTLS；尚未启用管理或配置证书')
                                    continue
                                if peer not in self.secure:
                                    if len(self.secure)>=64: raise DTLSError('DTLS session limit')
                                    send = lambda b,p=peer:self.sockets[0].sendto(b,p)
                                    options = {}
                                    if self.cookie_gate:
                                        state = self.cookie_gate.receive(peer,packet,send)
                                        if state is None: continue
                                        options['prestate'] = state
                                    session = self.session_class(self.credentials,send,**options)
                                    self.secure[peer] = {'session':session,'created':now,'seen':now}
                                entry = self.secure[peer]; entry['seen'] = now
                                for plain in entry['session'].feed(packet): self._consume(peer,plain,True)
                            else: self._consume(peer,packet,False)
                        except (ValueError,RuntimeError,OSError) as e:
                            self.log(peer[0]+': '+str(e))
                            if peer in self.secure:
                                self.secure.pop(peer)['session'].close()
                    self.engine.tick()
                    for peer,entry in list(self.secure.items()):
                        now = time.monotonic()
                        try:
                            if now-entry['seen']>90 or (not entry['session'].ready and now-entry['created']>20):
                                raise DTLSError('DTLS timeout')
                            for plain in entry['session'].poll(): self._consume(peer,plain,True)
                        except (ValueError,RuntimeError,OSError) as e:
                            self.log(peer[0]+': '+str(e))
                            self.secure.pop(peer)['session'].close()
        except Exception as e:
            self.error = str(e); self.log('服务错误：'+str(e))
            if not self.ready.done(): self.ready.set_exception(e)
        finally:
            with self.lock:
                self.running = False
                for entry in self.secure.values(): entry['session'].close()
                self.secure.clear()
                if self.credentials: self.credentials.close(); self.credentials = None
                for sock in self.sockets: sock.close()
                self.sockets.clear()
                while not self.commands.empty():
                    future,*_ = self.commands.get_nowait()
                    future.set_exception(RuntimeError('服务已停止'))
            self.log('CAPWAP 已停止')
