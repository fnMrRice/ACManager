"""Read-only network observations plus controller-local terminal names."""
import csv
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import time
import uuid
from .telemetry import STA_TTL


def local_hosts(leases=Path('/tmp/dhcp.leases'), arp=Path('/proc/net/arp'), now=None):
    now = time.time() if now is None else now
    hosts = {}
    try:
        for line in arp.read_text().splitlines()[1:4097]:
            fields = line.split()
            if len(fields) >= 6 and int(fields[2], 16) & 2:
                hosts[fields[3].lower()] = {'ip':str(ipaddress.ip_address(fields[0]))}
    except (OSError, ValueError): pass
    try:
        for line in leases.read_text().splitlines()[:4096]:
            fields = line.split()
            if len(fields) < 4: continue
            try:
                expiry = int(fields[0])
                if expiry and expiry < now: continue
                ip = str(ipaddress.IPv4Address(fields[2]))
            except ValueError: continue
            hosts[fields[1].lower()] = {'ip':ip, 'hostname':fields[3] if fields[3]!='*' else ''}
    except OSError: pass
    return hosts


class Monitor:
    def __init__(self, app, clock=time.monotonic, host_reader=local_hosts):
        self.app, self.clock, self.host_reader = app, clock, host_reader
        self.names, self.history = {}, {}
        self.path = app.data/'terminals.json'
        try:
            saved=json.loads(self.path.read_text(encoding='utf8'))
            if isinstance(saved,dict):
                self.names={k:v for k,v in saved.items() if re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',k)
                            and isinstance(v,str) and len(v.encode('utf8'))<=64}
        except (OSError, ValueError): pass

    def controller_info(self):
        try: mac=Path('/sys/class/net/br-lan/address').read_text().strip().lower()
        except OSError: mac=''
        if not mac:
            raw='%012x'%uuid.getnode();mac=':'.join(raw[i:i+2] for i in range(0,12,2))
        return {'dev_alias':'TP-LINK AP', 'ip':self.app.config['ac_ip'], 'mac':mac}

    def rows(self):
        app, now = self.app, self.clock()
        aps={a['mac']:a for a in app.ap_rows()}
        snapshot=app.service.snapshot()
        hosts=self.host_reader()
        candidates={}
        for ap in snapshot['aps']:
            parent=aps.get(ap.get('mac'))
            if not parent: continue
            for mac, station in ap.get('stations',{}).items():
                key=(station['seen'], ap.get('last_seen',0))
                if mac not in candidates or key > candidates[mac][0]:
                    candidates[mac]=(key,ap,parent,station)
        for mac, (_, ap, parent, station) in candidates.items():
            prior=self.history.get(mac,{})
            online=(snapshot.get('running',False) and parent['management_state']=='managed'
                    and ap['state']=='run' and now-station['seen']<STA_TTL)
            radio,wlan=station['radio'],station.get('wlan')
            ssid,vlan='未读取','---'
            for (sid,_), binding in app.bindings.items():
                if (binding.get('mac'),binding.get('radio'),binding.get('wlan'))==(parent['mac'],radio,wlan) and binding.get('active'):
                    ssid=app.profiles[sid]['ssid'];vlan=str(binding.get('vlan',0));break
            band=next((r.get('band','未知频段') for r in parent['radios'] if r['id']==radio),'未知频段').replace(' ','')
            host=hosts.get(mac,{})
            first=prior.get('_first',time.time())
            row={'id':mac.replace(':',''),'_row_id':mac.replace(':',''),'mac':mac,
                 'hostname':self.names.get(mac) or host.get('hostname') or mac,
                 'name':self.names.get(mac) or host.get('hostname') or mac,
                 'ip':host.get('ip','---'),'ipv6':'','type':'wireless','data_type':'sta_info',
                 'ap_name':parent['entry_name'],'ap_mac':parent['mac'],'ap_ip':parent['ip'],
                 'entry_id':parent['entry_id'],'group_id':parent['group_id'],
                 'online_status':'1' if online else '0','blocked':'0','auth_type':'unknown',
                 'ssid':ssid,'vlan_id':vlan,'freq_unit':str(radio),'freq_name':band,
                 'rssi':station.get('rssi'), 'nego_rate':station.get('nego_rate'),
                 'upstream_rate':station.get('upstream_rate') if online else None,
                 'downstream_rate':station.get('downstream_rate') if online else None,
                 'connect_date':'','connect_time':'','last_seen_seconds':round(max(0,now-station['seen']),1),
                 '_seen':station['seen'],'_first':first}
            row['rf_entry']=[{'freq_unit':str(radio),'freq_name':band,'rssi':row['rssi'],'nego_rate':row['nego_rate']}]
            self.history[mac]=row
        rows=[]
        for mac,row in list(self.history.items()):
            age=now-row['_seen']
            if age>3600:
                del self.history[mac];continue
            if mac not in candidates or age>=STA_TTL or not snapshot.get('running'):
                row=row|{'online_status':'0','upstream_rate':None,'downstream_rate':None}
            blocked=getattr(self.app,'station_policy',None)
            rule_names=blocked.rules if blocked else {}
            row=row|{'hostname':rule_names.get(mac,self.names.get(mac,row['hostname'])),'name':self.names.get(mac,row['name']),
                     'blocked':'1' if mac in rule_names else '0',
                     'last_seen_seconds':round(max(0,age),1)}
            rows.append({k:v for k,v in row.items() if k not in ('_seen','_first')})
        blocked=getattr(self.app,'station_policy',None)
        seen={r['mac'] for r in rows}
        for mac,name in (blocked.rules if blocked else {}).items():
            if mac not in seen:
                rows.append({'id':mac.replace(':',''),'_row_id':mac.replace(':',''),'mac':mac,
                    'hostname':name,'name':name,'blocked':'1','online_status':'0','type':'wireless',
                    'data_type':'sta_info','ip':'---','ap_name':'---','ap_mac':'','ap_ip':'',
                    'ssid':'---','freq_name':'---','auth_type':'unknown'})
        return sorted(rows,key=lambda r:(r['online_status']!='1',r['ap_name'],r['mac']))

    def rename(self, mac, name):
        mac=str(mac).lower().replace('-',':')
        if not isinstance(name,str) or not name.strip() or len(name.encode('utf8'))>64 or any(ord(c)<32 for c in name):
            raise ValueError('终端名称需为 1–64 字节，不能含控制字符')
        if not any(r['mac']==mac for r in self.rows()): raise ValueError('未找到该终端，请刷新列表')
        policy=getattr(self.app,'station_policy',None)
        if policy and mac in policy.rules:
            policy.commit(policy.rules|{mac:name.strip()})
        names=self.names|{mac:name.strip()}
        temporary=self.path.with_suffix('.tmp')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w',encoding='utf8') as stream:
            json.dump(names,stream,ensure_ascii=False);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,self.path);self.names=names

    def topology(self, kind='all'):
        if kind not in ('all','online','offline'): raise ValueError('无效设备筛选')
        root=self.controller_info()
        nodes=[{'deviceIndex':'mainDeviceIndex','mac':root['mac'],'devName':root['dev_alias'],
                'ip':root['ip'],'devType':'AC','onlineStatus':1},
               {'mac':'logical-network','devName':'管理网络','onlineStatus':1}]
        edges=[]
        def edge(source, target, wireless=False):
            index=str(len(edges))
            edges.append({'srcMac':source,'destMac':target,
                          'srcPort':'Wireless' if wireless else 'notDrawPort-src-'+index,
                          'destPort':'Wireless' if wireless else 'notDrawPort-dst-'+index})
        edge(root['mac'],'logical-network')
        groups=set()
        visible=set()
        for ap in self.app.ap_rows():
            online=ap['management_state']=='managed'
            if kind=='online' and not online or kind=='offline' and online: continue
            visible.add(ap['mac'])
            group='ap-group-'+ap['group_id']
            if group not in groups:
                nodes.append({'mac':group,'devName':ap['group_name'],'devType':'CUSTOMGROUP','isCustomGroup':True,'open':True})
                edge('logical-network',group);groups.add(group)
            nodes.append({'mac':ap['mac'],'devName':ap['entry_name'],'ip':ap['ip'],
                          'devType':'AP','onlineStatus':int(online),'belongDevice':'mainDeviceIndex',
                          'description':ap['management_label']})
            edge(group,ap['mac'])
        clients=0
        for row in self.rows():
            if row['online_status']!='1' or row['ap_mac'] not in visible: continue
            nodes.append({'mac':row['mac'],'devName':row['hostname'],'ip':row['ip'] if row['ip']!='---' else '',
                          'devType':'CLIENT','onlineStatus':1})
            edge(row['ap_mac'],row['mac'],True);clients+=1
        return {'devList':nodes,'edgeList':edges,'ap_count':len(visible),'client_count':clients}

    def csv(self):
        out=io.StringIO(newline='')
        writer=csv.writer(out)
        writer.writerow(['终端名称','MAC地址','IP地址','AP名称','AP地址','SSID','频段','信号强度(dBm)','协商速率(Mbps)','上行(Kbps)','下行(Kbps)','状态'])
        for row in self.rows():
            values=[row.get(k) for k in ('hostname','mac','ip','ap_name','ap_ip','ssid','freq_name','rssi','nego_rate','upstream_rate','downstream_rate')]
            # Exported names must not become spreadsheet formulas.
            values=["'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v for v in values]
            writer.writerow(values+['在线' if row['online_status']=='1' else '离线'])
        return ('\ufeff'+out.getvalue()).encode('utf8')
