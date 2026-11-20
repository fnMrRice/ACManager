"""Portable controller state machine. Every operation awaits an AP ACK.

Responses are reconstructed, not hardware-certified. Unknown extensions remain
visible in status and are not treated as successful configuration.
"""
import hashlib
import socket
import struct
import time
import uuid
from .protocol import (ProtocolError, encode, decode, tlv, vendor, identity,
                       wlan_elements, delete_wlan_elements, wlan_report, WLAN_REQUEST, WLAN_RESPONSE, NAMES)
from .adoption import permitted
from . import telemetry

class Controller:
    def __init__(self, config, send, clock=time.monotonic):
        self.config, self.send, self.clock = config, send, clock
        self.peers, self.sequence = {}, 0
        self.results = {}
        self.read_requests = {}
        self.blocked_stations = frozenset()
        from .balance import Decisions
        self.balance=Decisions()

    def record(self,ap,result):
        ap['last_operation'] = result
        self.results[result['id']] = result
        while len(self.results)>128: del self.results[next(iter(self.results))]

    def allowed(self, peer):
        ap=self.peers.get(peer,{})
        if not ap.get('mac'):
            # DTLS changes source ports. Use the latest discovered identity,
            # never permanently exclude an address previously used by a MAC.
            candidates=[a for p,a in self.peers.items() if p[0]==peer[0] and a.get('mac')]
            ap=max(candidates,key=lambda a:a['last_seen'],default={})
        return permitted(self.config,peer[0],ap.get('mac'))

    def descriptor(self):
        security = 2 if self.config.get('dtls', False) else 0
        desc = struct.pack('!HHHHBBBB', 0, 1024, len(self.peers), 64, security, 2, 0, 4)
        for kind, value in ((4, b'OpenWrt TP-LINK AC experimental'), (5, b'0.1.0')):
            desc += struct.pack('!IHH', 0x12345678, kind, len(value)) + value
        return tlv(1, desc) + tlv(4, self.config.get('name', 'OpenWrt AC').encode('utf-8')[:128])

    def common(self, message):
        address = socket.inet_aton(self.config['ac_ip'])
        out = self.descriptor() + tlv(10, address + b'\0\0')
        out += vendor(0, b'\x00\x01\x00\x01')
        for value in message.values(1048):
            if len(value) == 5: out += tlv(1048, value)
        return out

    def receive(self, peer, data, secure=False):
        message = decode(data)
        now = self.clock()
        established = self.peers.get(peer)
        if established and established['secure'] and not secure:
            if message.kind==1 and self.allowed(peer):
                self.send(peer,encode(2,message.sequence,self.common(message),0,message.binding),False)
            return
        info = identity(message)
        if peer not in self.peers:
            if len(self.peers) >= 64:
                oldest = min(self.peers, key=lambda p: self.peers[p]['last_seen'])
                if now - self.peers[oldest]['last_seen'] < 120:
                    raise ProtocolError('AP session limit reached')
                del self.peers[oldest]
            self.peers[peer] = {'ip': peer[0], 'port': peer[1], 'state': 'observed',
                                'private_types': [], 'radio_ids': [], 'pending': None,
                                'last_operation': None, 'cache': {}, 'secure': secure}
        ap = self.peers[peer]
        previous_mac = ap.get('mac')
        if previous_mac and info.get('mac', previous_mac) != previous_mac:
            raise ProtocolError('AP identity changed within session')
        for key, value in info.items():
            if key == 'private_types': ap[key] = sorted(set(ap[key]) | set(value))
            elif value: ap[key] = value
        ap.update(last_seen=now, message=NAMES.get(message.kind, str(message.kind)))
        if not self.allowed(peer):
            ap['reason'] = 'observation only / IP not allowed'
            return
        if message.kind!=1 and self.config.get('discovery_only'):
            ap['reason'] = 'discovery reply only; joining is disabled'
            return
        if message.kind != 1:
            if self.config.get('dtls', False) and not secure:
                ap['reason'] = 'DTLS required'
                return
            if not secure and not self.config.get('allow_plaintext', False):
                ap['reason'] = 'plaintext control disabled'
                return
        ap['secure'] = secure
        if secure:
            for value in message.values(32):
                if len(value)==3 and value[0] in ap['radio_ids'] and value[1] in (1,2):
                    ap.setdefault('radio_states',{})[str(value[0])]='on' if value[1]==1 else 'off'
            report = wlan_report(message)
            if report is not None:
                ap['reported_wlans'] = report
                ap['wlan_report_time'] = now
            for value in message.values(1026):
                if len(value)==8:
                    bssids=ap.setdefault('reported_bssids',{})
                    bssids[str(value[0])+':'+str(value[1])]=':'.join('%02x'%v for v in value[2:])
        # Duplicate UDP request must return the same response, without applying
        # state changes again. Hash covers content, not only wrapped sequence.
        cache_key = hashlib.sha256(data).digest()
        cached = ap['cache'].get(cache_key)
        if cached and now - cached[0] < 30:
            self.send(peer, cached[1], secure)
            return
        if secure and message.kind == 9 and ap['state'] == 'run':
            try:
                telemetry.receive(ap, message, now)
                ap.pop('telemetry_error', None)
            except ProtocolError as error:
                # An unfamiliar statistics dialect must not tear down DTLS.
                ap['telemetry_error'] = str(error)
        response = None
        if message.kind == 1:
            if ap['state'] in ('observed', 'discovered'):
                ap['state'] = 'discovered'
            response = self.common(message)
        elif message.kind == 3:
            sid = message.values(35)
            if len(sid) != 1 or len(sid[0]) != 16 or not ap.get('mac'):
                ap['reason'] = 'join needs board MAC and 16-byte session ID'
                return
            ap.update(state='joined', session_id=sid[0].hex(), session_epoch=uuid.uuid4().hex, pending=None)
            for key in ('run_since','telemetry_requested','telemetry_status','station_report_time','stations',
                        'radio_statistics','radio_report_time','reported_bssids','radio_states'):
                ap.pop(key, None)
            response = tlv(33, bytes(4)) + self.common(message)
            response += tlv(53, b'\x00') + tlv(30, socket.inet_aton(self.config['ac_ip']))
            response += vendor(29, struct.pack('!I', 2)) + vendor(39, bytes(4))
        elif message.kind == 5 and ap['state'] in ('joined', 'configured', 'run'):
            ap['state'] = 'configured'
            response = tlv(12, bytes((20,20))) + tlv(23, struct.pack('!I', 3600))
            response += tlv(40, b'\x01') + tlv(2, socket.inet_aton(self.config['ac_ip']))
            for radio in ap['radio_ids']:
                response += tlv(16, struct.pack('!BH', radio, 120))
        elif message.kind == 11 and ap['state'] in ('configured', 'run'):
            ap['state'] = 'run'
            response = b''
        elif message.kind == 13 and ap['state'] in ('configured', 'run'):
            # Some firmware transitions directly from CONFIGURE to RUN.
            ap['state'] = 'run'
            response = b''
        elif message.kind == 9 and ap['state'] == 'run':
            response = tlv(33, bytes(4))
            if secure:
                from .readback import response as read_response
                for raw in message.private(131):
                    if len(raw)<4: continue
                    ident=struct.unpack_from('!I',raw)[0]
                    request=self.read_requests.get(ident)
                    if not request or request['peer']!=peer or request['epoch']!=ap.get('session_epoch') or request['expires']<now: continue
                    try:
                        _,data=read_response(raw)
                        request['result']={'data':data}
                    except ProtocolError:
                        request['result']={'error':'AP 返回的配置读取数据格式无效'}
            if secure and message.private(11):
                try:
                    self.balance.observe(ap,message,now)
                    ap['balance_probe_reports']=ap.get('balance_probe_reports',0)+len(message.private(11))
                    ap.pop('balance_probe_error',None)
                except ProtocolError as error:
                    # Discovery observations are optional telemetry, not a
                    # reason to close the AP's authenticated control channel.
                    ap['balance_probe_error']=str(error)
                    ap['balance_probe_sample']=[raw[:32].hex() for raw in message.private(11)[:4]]
            if secure and (message.private(2) or message.private(138)):
                from .station_policy import association_results
                try:
                    from .protocol import parse_tlvs
                    replies=association_results(message,self.blocked_stations,decide=lambda radio,wlan,mac:
                        self.balance.decide(ap,radio,mac,list(self.peers.values()),now))
                    denied=sum(int.from_bytes(value[14:18],'big')!=0 for kind,value in parse_tlvs(replies))
                    ap['balance_rejections']=ap.get('balance_rejections',0)+sum(
                        int.from_bytes(value[14:18],'big')==39 for kind,value in parse_tlvs(replies))
                    response=tlv(33,struct.pack('!I',21 if denied else 0))+replies
                    ap['association_requests']=ap.get('association_requests',0)+len(message.private(2))+len(message.private(138))
                    ap['association_denials']=ap.get('association_denials',0)+denied
                    ap.pop('admission_error',None)
                except ProtocolError as error:
                    ap['admission_error']=str(error)
                    response=tlv(33,struct.pack('!I',21))
        elif message.kind in (8, 18, 26, WLAN_RESPONSE):
            pending = ap['pending']
            if pending and (message.kind, message.sequence) == (pending['response'], pending['sequence']):
                results = message.values(33)
                if len(results) != 1 or len(results[0]) != 4:
                    self.record(ap,{'status': 'unconfirmed', 'action': pending['action'],
                                            'id':pending['id'],
                                            'reason': 'response has no unique valid Result Code'})
                else:
                    result = struct.unpack('!I', results[0])[0]
                    self.record(ap,{'status': 'acknowledged' if result == 0 else 'rejected',
                                    'action': pending['action'], 'result_code': result,'id':pending['id']})
                    if result==0 and pending['action'] in ('led_on','led_off'):
                        ap['led'] = str(int(pending['action']=='led_on'))
                    if result==0 and pending['action']=='radio' and 'rf_state' in pending['profile']:
                        ap.setdefault('radio_states',{})[str(pending['profile']['radio'])]=pending['profile']['rf_state']
                    if result==0 and pending['action'] in ('reboot','factory_reset'):
                        ap['state']='restarting'
                    if result==0 and pending['action']=='admission': ap['admission_control']='acknowledged'
                ap['pending'] = None
                if pending['action'] == 'statistics':
                    ap['telemetry_status'] = ap['last_operation']['status']
            return
        else:
            ap['reason'] = 'unsupported message or invalid state: ' + str(message.kind)
            return
        ap.pop('reason', None)
        if response is not None:
            packet = encode(message.kind + 1, message.sequence, response, 0, message.binding)
            self.send(peer, packet, secure)
            ap['cache'][cache_key] = (now, packet)
            ap['cache'] = {k:v for k,v in list(ap['cache'].items())[-16:] if now-v[0] < 30}

    def operation(self, ip, action, profile=None):
        if not self.config.get('enabled'):
            raise ProtocolError('当前为观察模式，只能发现 AP；尚未建立管理连接，不能下发指令')
        if self.config.get('discovery_only'):
            raise ProtocolError('当前仅回复发现请求，尚未接管 AP，不能下发指令')
        matches = [(p,a) for p,a in self.peers.items() if p[0] == ip and a['state'] == 'run'
                   and self.clock() - a['last_seen'] < 90]
        if len(matches) != 1:
            raise ProtocolError('该 AP 尚未建立唯一有效的管理连接；发现设备不代表已经接管')
        peer, ap = matches[0]
        if not self.allowed(peer): raise ProtocolError('AP IP not authorized')
        if self.config.get('dtls') and not ap['secure']: raise ProtocolError('DTLS session required')
        if ap['pending']: raise ProtocolError('another operation awaits acknowledgement')
        if action in ('wireless_read','wireless_patch'):
            from .readback import query,patch
            if not ap['secure']: raise ProtocolError('配置读取需要加密管理连接')
            fields={'request_id'} if action=='wireless_read' else {'request_id','section','changes'}
            if not isinstance(profile,dict) or set(profile)!=fields: raise ValueError('invalid wireless request')
            ident=profile['request_id']
            body=query(ident) if action=='wireless_read' else patch(ident,profile['section'],profile['changes'])
            if ident in self.read_requests: raise ValueError('duplicate read request')
            if len(self.read_requests)>=32: raise ValueError('too many read requests')
            self.read_requests[ident]={'peer':peer,'epoch':ap.get('session_epoch'),'expires':self.clock()+30}
            kind,response=7,8
        elif action == 'statistics':
            body = telemetry.statistics_control()
            kind, response = 7, 8
        elif action == 'disconnect':
            from .station_policy import delete_station
            body=delete_station(ap,profile,self.clock())
            kind,response=25,26
        elif action == 'band_navigation':
            from .features import band_elements
            body=band_elements(ap,profile)
            kind,response=7,8
        elif action == 'balance':
            from .balance import elements
            body=elements(profile)
            kind,response=7,8
        elif action == 'edca':
            from .edca import elements
            body=elements(ap,profile)
            kind,response=7,8
        elif action == 'admission':
            from .station_policy import admission_elements
            body=admission_elements(profile)
            kind,response=7,8
        elif action in ('reboot','factory_reset'):
            # apmngr_pkt_reset_pkt_send(1): bare reboot.
            # apmngr_ap_reset passes 3, which serializes vendor reset mask 3.
            if profile: raise ProtocolError('重启或恢复出厂不接受额外参数')
            body=b'' if action=='reboot' else vendor(35,struct.pack('!I',3))
            kind,response=17,18
        elif action == 'radio':
            from .radio import radio_elements
            body=radio_elements(ap,profile)
            kind,response=7,8
        elif action == 'apply':
            if not profile: raise ProtocolError('wireless profile missing')
            profile = dict(profile)
            dialect = profile.pop('dialect', 'auto')
            if dialect=='auto': dialect=ap.get('wireless_dialect','auto')
            if dialect == 'auto':
                advertised = set(ap['private_types']) & {9,99}
                if len(advertised) != 1:
                    raise ProtocolError('service dialect not established; select legacy9 or modern99 after validation')
                dialect = advertised.pop()
            else:
                dialect = {'legacy9':9, 'modern99':99}.get(dialect)
            if dialect is None: raise ProtocolError('unsupported service dialect')
            radio = int(profile.get('radio',1))
            if radio not in ap['radio_ids']:
                raise ProtocolError('selected radio was not advertised by AP')
            body = wlan_elements(dialect=dialect, **profile)
            kind, response = WLAN_REQUEST, WLAN_RESPONSE
        elif action=='remove':
            if not isinstance(profile,dict) or set(profile)!={'radio','wlan'}:
                raise ProtocolError('remove requires a specific radio and WLAN')
            radio,wlan=int(profile['radio']),int(profile['wlan'])
            if radio not in ap['radio_ids']: raise ProtocolError('selected radio was not advertised by AP')
            body=delete_wlan_elements(radio,wlan)
            kind,response=WLAN_REQUEST,WLAN_RESPONSE
        elif action in ('led_on','led_off'):
            body = vendor(57, struct.pack('!I', int(action == 'led_on')))
            kind, response = 7, 8
        else:
            raise ProtocolError('unsupported action')
        self.sequence = (self.sequence + 1) % 256
        packet = encode(kind, self.sequence, body)
        now = self.clock()
        operation_id = uuid.uuid4().hex
        ap['pending'] = {'sequence':self.sequence, 'response':response, 'packet':packet,'id':operation_id,
                         'sent':now, 'tries':1, 'action':action}
        if action=='radio': ap['pending']['profile']=dict(profile)
        self.record(ap,{'status':'pending', 'action':action,'id':operation_id})
        try: self.send(peer, packet, ap['secure'])
        except (OSError,ValueError,RuntimeError):
            ap['pending'] = None
            self.record(ap,{'status':'send_failed','action':action,'id':operation_id})
            raise
        return {'status':'pending', 'sequence':self.sequence,'id':operation_id}

    def tick(self):
        now = self.clock()
        self.read_requests={k:v for k,v in self.read_requests.items() if v['expires']>now}
        for peer, ap in list(self.peers.items()):
            if ap['state'] == 'run' and ap['secure']:
                ap.setdefault('run_since', now)
                if (now-ap['run_since'] >= 10 and not ap.get('telemetry_requested')
                        and not ap['pending'] and self.allowed(peer)):
                    ap['telemetry_requested'] = True
                    try:
                        self.operation(peer[0], 'statistics')
                        ap['telemetry_status'] = 'pending'
                    except (ValueError, RuntimeError, OSError) as error:
                        ap['telemetry_status'] = 'failed'
                        ap['telemetry_error'] = str(error)
            if now - ap['last_seen'] > 90:
                ap['state'] = 'offline'
                if ap['pending']:
                    self.record(ap,{'status':'timeout', 'action':ap['pending']['action'],'id':ap['pending']['id']})
                    ap['pending'] = None
            pending = ap['pending']
            if pending and now - pending['sent'] >= 3:
                if pending['tries'] >= 3 or not self.allowed(peer):
                    self.record(ap,{'status':'timeout', 'action':pending['action'],'id':pending['id']})
                    ap['pending'] = None
                else:
                    try:
                        self.send(peer, pending['packet'], ap['secure'])
                        pending.update(sent=now, tries=pending['tries'] + 1)
                    except (OSError,ValueError,RuntimeError):
                        self.record(ap,{'status':'send_failed','action':pending['action'],'id':pending['id']})
                        ap['pending'] = None
            if now - ap['last_seen'] > 3600: del self.peers[peer]

    def status(self):
        from copy import deepcopy
        # Consumers retain snapshots while awaiting AP replies. Nested station
        # maps must not change underneath HTTP serialization or batch actions.
        return deepcopy({'experimental':True, 'hardware_verified':False, 'enabled':self.config.get('enabled',False),
                'operations':dict(self.results),
                'aps':[{k:v for k,v in ap.items() if k not in ('cache','pending','session_id','serial')}
                       | {'last_seen_seconds':round(self.clock()-ap['last_seen'],1)}
                       for ap in self.peers.values()]})
