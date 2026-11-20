"""Session load balancing using AP discovery reports and association decisions.

Wire evidence: balance_packet_send (0x4ed65c), cw_priv_sta_dis_parse,
cw_priv_spec_rssi_assemble, balance_db_dis_sta_check (60 s retry window),
balance_wsta_callback_balance_sta_check (association result 39).
"""
from copy import deepcopy
import json
import os
import struct
import time
from .protocol import ProtocolError, vendor
from .radio import integer
from .station_policy import canonical_mac
from .telemetry import STA_TTL, mac_text

DEFAULTS={'name':'','enable':'on','mode':'session','usr_threshold':'20',
          'dif_threshold':'4','max_fail_num':'3','rssi_threshold':'-75'}


def settings(value):
    if not isinstance(value,dict) or set(value)!=set(DEFAULTS): raise ValueError('负载均衡参数不完整')
    name=value['name']
    if not isinstance(name,str) or not name.strip() or len(name.encode('utf8'))>50 or any(ord(c)<32 for c in name):
        raise ValueError('规则名称需为 1–50 字节')
    if value['enable'] not in ('on','off') or value['mode']!='session':
        raise ValueError('仅支持终端数量负载均衡')
    out=dict(value);out['name']=name.strip()
    for field,low,high in (('usr_threshold',1,100),('dif_threshold',1,15),('max_fail_num',1,100),('rssi_threshold',-95,0)):
        n=integer(value[field])
        if not low<=n<=high: raise ValueError('负载均衡参数超出范围：'+field)
        out[field]=str(n)
    return out


def elements(value):
    value=settings(value);enabled=value['enable']=='on'
    # Probe reporting uses only mask bit 0. Do not disable association checks
    # when disabling balance; the blacklist also needs those checks.
    # Combine the original admission mask 6f/2e and balance bit 1/1
    # into one element: some AP codecs only consume one value per type.
    body=vendor(38,struct.pack('!II',0x6f if enabled else 1,0x2f if enabled else 0))
    if enabled: body+=vendor(62,struct.pack('!i',int(value['rssi_threshold'])))
    return body


class Decisions:
    def __init__(self):
        self.rules={};self.probes={};self.failures={}

    def configure(self,rules):
        if self.rules!=rules:
            self.rules=deepcopy(rules);self.failures.clear()

    def observe(self,ap,message,now):
        observations=[]
        for raw in message.private(11):
            if len(raw)!=8 or raw[0] not in ap.get('radio_ids',[]): raise ProtocolError('invalid station discovery')
            observations.append((mac_text(raw[2:8]),raw[0]))
        self.probes={k:v for k,v in self.probes.items() if now-v<60}
        for mac,radio in observations:
            self.probes[(mac,ap.get('mac'),radio)]=now
        while len(self.probes)>4096:self.probes.pop(next(iter(self.probes)))

    def decide(self,ap,radio,mac,peers,now):
        rule=next((r for r in self.rules.values() if r['enable']=='on' and
                   r['epochs'].get(ap.get('mac'))==ap.get('session_epoch') and ap.get('session_epoch')),None)
        if not rule:return 0
        if now-ap.get('station_report_time',float('-inf'))>=STA_TTL:return 0
        key=(rule['id'],mac)
        count,last=self.failures.get(key,(0,now))
        if now-last>=60:count=0
        if count>=int(rule['max_fail_num']):return 0
        def total(a):return sum(now-s['seen']<STA_TTL for s in a.get('stations',{}).values())
        current=total(ap)
        if current<int(rule['usr_threshold']):return 0
        band=next((r.get('band') for r in ap.get('radios',[]) if r['id']==radio),None)
        ssids={r['ssid'] for r in ap.get('reported_wlans',[]) if r['radio']==radio}
        if not band or not ssids:return 0
        for other in peers:
            if (other.get('mac')==ap.get('mac') or other['state']!='run' or now-other['last_seen']>=90
                    or now-other.get('station_report_time',float('-inf'))>=STA_TTL
                    or not other.get('session_epoch') or rule['epochs'].get(other.get('mac'))!=other['session_epoch']):continue
            for rd in other.get('radios',[]):
                if rd.get('band')!=band:continue
                heard=self.probes.get((mac,other['mac'],rd['id']))
                if heard is None or now-heard>=60:continue
                other_ssids={r['ssid'] for r in other.get('reported_wlans',[]) if r['radio']==rd['id']}
                if not ssids&other_ssids:continue
                if current-total(other)>=int(rule['dif_threshold']):
                    self.failures[key]=(count+1,now)
                    while len(self.failures)>4096:self.failures.pop(next(iter(self.failures)))
                    return 39
        return 0


class Balance:
    def __init__(self,app):
        self.app=app;self.path=app.data/'balance.json';self.rules={};self.retry={}
        if self.path.exists():
            saved=json.loads(self.path.read_text(encoding='utf8'))
            if saved.get('version')!=1:raise ValueError('负载均衡配置版本不支持')
            self.rules=saved['rules']
            for rule in self.rules.values():
                settings(rule['settings'])
                for mac in rule['macs']:canonical_mac(mac)

    def save(self):
        temp=self.path.with_suffix('.tmp');fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w',encoding='utf8') as f:
            json.dump({'version':1,'rules':self.rules},f,ensure_ascii=False);f.flush();os.fsync(f.fileno())
        os.replace(temp,self.path);self.sync()

    def sync(self):
        self.app.service.update_balance({rid:rule['settings']|{'id':rid,
            'epochs':{mac:t.get('epoch') for mac,t in rule['targets'].items() if t.get('status')=='acknowledged'}}
            for rid,rule in self.rules.items() if not rule.get('deleting')})

    def rows(self):
        aps={a['mac']:a for a in self.app.ap_rows()};rows=[]
        for rid,rule in self.rules.items():
            ready=sum(t.get('status')=='acknowledged' and t.get('epoch')==aps.get(mac,{}).get('session_epoch')
                      and aps.get(mac,{}).get('management_state')=='managed' for mac,t in rule['targets'].items())
            rows.append(rule['settings']|{'id':rid,'group_ids':[],'group_id_str':'',
                'ap_ids':[aps[m]['entry_id'] for m in rule['macs'] if m in aps],
                'apply_status':('删除中' if rule.get('deleting') else 'AP 已确认' if ready==len(rule['targets']) else '等待下发')+
                               ' '+str(ready)+'/'+str(len(rule['targets']))})
        return rows

    def mutate(self,method,request):
        aps=self.app.ap_rows();by_id={a['entry_id']:a for a in aps};by_mac={a['mac']:a for a in aps}
        ids=self.app.filter_ids(request,'id')
        if method=='add':
            if len(self.rules)>=32:raise ValueError('最多 32 条负载均衡规则')
            rid=str(max([int(i) for i in self.rules]+[0])+1);previous=None
        elif method in ('set','delete'):
            if not ids or any(i not in self.rules for i in ids):raise ValueError('未找到负载均衡规则')
            if len(ids)!=1:raise ValueError('请逐条修改或删除负载均衡规则')
            rid=ids[0];previous=self.rules[rid]
        else:raise ValueError('无效负载均衡操作')
        if method=='delete':
            candidate=deepcopy(previous);candidate['settings']['enable']='off';candidate['deleting']=True
        else:
            para=dict(request.get('para',{}));allowed=set(DEFAULTS)|{'ap_ids','group_ids','index_field'}
            if set(para)-allowed:raise ValueError('不支持的负载均衡字段')
            candidate=deepcopy(previous) if previous else {'macs':[],'targets':{}}
            candidate['settings']=settings((previous['settings'] if previous else DEFAULTS)|{k:v for k,v in para.items() if k in DEFAULTS})
            if 'group_ids' in para or 'ap_ids' in para:
                groups=para.get('group_ids',[]);apids=para.get('ap_ids',[])
                if not isinstance(groups,list) or not isinstance(apids,list):raise ValueError('请选择 AP')
                # Resolve selections to durable MAC identities at save time.
                if groups:raise ValueError('请选择具体 AP 设备；动态分组负载均衡尚未适配')
                if not apids or any(str(i) not in by_id for i in apids):raise ValueError('未找到所选 AP')
                candidate['macs']=sorted({by_id[str(i)]['mac'] for i in apids})
            if not candidate['macs']:raise ValueError('请选择 AP')
            if previous and candidate['macs']!=previous['macs']:raise ValueError('修改 AP 范围请先删除原规则，再新建规则')
            for oid,other in self.rules.items():
                if oid==rid:continue
                if candidate['settings']['name']==other['settings']['name']:raise ValueError('规则名称重复')
                if set(candidate['macs'])&set(other['macs']):raise ValueError('所选 AP 已属于其他负载均衡规则')
        for mac in candidate['macs']:
            if by_mac.get(mac,{}).get('management_state')!='managed':raise ValueError('所选 AP 包含离线或未接管设备')
        candidate['targets']={m:{'status':'pending','epoch':None} for m in candidate['macs']}
        self.rules[rid]=candidate;self.save()
        for mac in candidate['macs']:self.apply(rid,by_mac[mac])
        if method=='delete':del self.rules[rid];self.save()
        return {'status':'acknowledged','apmng_balance':{'name':'rule_list_'+rid}}

    def apply(self,rid,ap):
        rule=self.rules[rid];target=rule['targets'][ap['mac']]
        try:self.app.confirm_action(ap['ip'],'balance',rule['settings'])
        except (ValueError,RuntimeError,OSError) as error:
            target.update(status='failed',error=str(error));self.save()
            raise ValueError('规则已保存，但 AP 下发未确认：'+ap['ip']+'；'+str(error)) from error
        target.clear();target.update(status='acknowledged',epoch=ap.get('session_epoch'))
        if rule['settings']['enable']=='on':
            self.app.station_policy.admission_aps[ap['mac']]={'epoch':ap.get('session_epoch')}
            self.app.station_policy.commit(self.app.station_policy.rules)
        self.save()

    def invalidate(self,mac):
        for rule in self.rules.values():
            if mac in rule['targets']:rule['targets'][mac]['epoch']=None
        self.sync()

    def forget_ap(self,mac):
        for rid,rule in list(self.rules.items()):
            rule['macs']=[m for m in rule['macs'] if m!=mac];rule['targets'].pop(mac,None)
            if not rule['macs']:del self.rules[rid]
        self.save()

    def reconcile(self):
        now=time.monotonic();aps={a['mac']:a for a in self.app.ap_rows()}
        for rid,rule in list(self.rules.items()):
            for mac,t in rule['targets'].items():
                ap=aps.get(mac,{})
                if (ap.get('management_state')!='managed' or not ap.get('session_epoch') or
                    t.get('status')=='acknowledged' and t.get('epoch')==ap['session_epoch'] or now<self.retry.get(mac,0)):continue
                self.retry[mac]=now+60
                try:self.apply(rid,ap)
                except (ValueError,RuntimeError,OSError) as error:self.app.service.log(str(error))
                return True
            if rule.get('deleting') and all(t.get('status')=='acknowledged' for t in rule['targets'].values()):
                del self.rules[rid];self.save()
