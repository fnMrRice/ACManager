"""MAC admission replies reconstructed from uac's association codecs.

Sources: cw_priv_sta_assoc_req[_new]_parse, cw_priv_sta_assoc_rslt[_new]_assemble,
mac_auth_wsta_callback_sta_check (40), _uac_wsta_del_cb (25 / element 18).
"""
import csv
import io
import json
import os
import re
import struct
from .protocol import ProtocolError, parse_tlvs, tlv, vendor
from .telemetry import mac_text, STA_TTL
import time


def canonical_mac(value):
    value=str(value).lower().replace('-', ':')
    if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',value):
        raise ValueError('MAC 地址格式错误')
    return mac_text(bytes.fromhex(value.replace(':','')))


def association_results(message, blocked, only_denied=False, decide=None):
    """Echo each request's opaque association context with the AC decision."""
    replies=[]
    for kind in (2,138):
        for data in message.private(kind):
            if len(data)<8: raise ProtocolError('short association request')
            mac=mac_text(data[2:8])
            status=40 if mac in blocked else 0
            if only_denied and not status: continue
            if not 1<=data[0]<=31 or not 1<=data[1]<=16:
                raise ProtocolError('invalid association radio/WLAN')
            if kind==2:
                # Legacy APs optionally include RSSI before the opaque tail.
                tails=[data[offset+4:] for offset in (8,12)
                       if len(data)>=offset+4 and int.from_bytes(data[offset:offset+4],'big')==len(data)-offset-4]
                if len(tails)!=1: raise ProtocolError('ambiguous legacy association length')
                tail=tails[0]
                if not status and decide:status=decide(data[0],data[1],mac)
                replies.append(vendor(4,data[:8]+struct.pack('!II',status,len(tail))+tail))
            else:
                if len(data)<17 or int.from_bytes(data[13:17],'big')!=len(data)-17:
                    raise ProtocolError('invalid modern association length')
                fields=parse_tlvs(data[17:])
                if len({k for k,_ in fields})!=len(fields): raise ProtocolError('duplicate association subelement')
                extra=b''.join(tlv(1,v) if k==0 else tlv(2,b'') if k==1 else b'' for k,v in fields)
                # Multi-link requests need per-link decisions; don't apply
                # legacy session balancing to those until that codec exists.
                if not status and decide and not any(k==1 for k,v in fields):status=decide(data[0],data[1],mac)
                replies.append(vendor(139,data[:8]+struct.pack('!IBI',status,data[12],len(extra))+extra))
    return b''.join(replies)


def association_denials(message,blocked):
    return association_results(message,blocked,only_denied=True)


def admission_elements(profile):
    if not isinstance(profile,dict) or set(profile)!={'enable'} or profile['enable'] is not True:
        raise ProtocolError('接入检查仅支持显式开启')
    # _apmngr_pkt_config_status_req_listen sends mask=0x6f, switch=0x2e.
    # This matches the original AC rather than guessing individual mask bits.
    return vendor(38,struct.pack('!II',0x6f,0x2e))


def delete_station(ap, profile, now):
    if not isinstance(profile,dict) or set(profile)!={'mac'}:
        raise ProtocolError('disconnect requires one station MAC')
    mac=canonical_mac(profile['mac'])
    station=ap.get('stations',{}).get(mac)
    if not station or now-station['seen']>=STA_TTL or station['radio'] not in ap['radio_ids']:
        raise ProtocolError('终端已离线或关联位置已改变，请刷新列表')
    return tlv(18,bytes((station['radio'],6))+bytes.fromhex(mac.replace(':','')))


class StationPolicy:
    fields=('MAC地址','终端名称')

    def __init__(self,app):
        self.app=app
        self.path=app.data/'station-policy.json'
        self.rules={};self.admission_aps={};self.retry={}
        if self.path.exists():
            saved=json.loads(self.path.read_text(encoding='utf8'))
            if saved.get('version')!=1: raise ValueError('终端规则文件版本不支持')
            self.rules={canonical_mac(k):self.name(v) for k,v in saved['blocked'].items()}
            self.admission_aps={canonical_mac(k):v for k,v in saved.get('admission_aps',{}).items()}
        app.service.update_station_policy(self.rules)

    @staticmethod
    def name(value):
        if not isinstance(value,str) or not value.strip() or len(value.encode('utf8'))>64 or any(ord(c)<32 for c in value):
            raise ValueError('终端名称需为 1–64 字节，不能含控制字符')
        return value.strip()

    def commit(self,rules):
        if len(rules)>1024: raise ValueError('黑名单最多 1024 条')
        temporary=self.path.with_suffix('.tmp')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w',encoding='utf8') as stream:
            json.dump({'version':1,'blocked':rules,'admission_aps':self.admission_aps},stream,ensure_ascii=False)
            stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,self.path)
        self.rules=rules
        self.app.service.update_station_policy(rules)

    def admission_status(self):
        return [{'mac':ap['mac'],'name':ap['entry_name'],'ip':ap['ip'],
            'online':ap['management_state']=='managed',
            'status':('acknowledged' if self.admission_aps.get(ap['mac'],{}).get('epoch')==ap.get('session_epoch') and ap.get('session_epoch') else
                      'waiting_rejoin' if ap['mac'] in self.admission_aps else 'not_configured'),
            'requests':ap.get('association_requests',0),'denials':ap.get('association_denials',0)} for ap in self.app.ap_rows()]

    def enable_admission(self,macs):
        if not isinstance(macs,list) or not macs or len(macs)>64 or len(set(macs))!=len(macs): raise ValueError('请选择 AP')
        aps={a['mac']:a for a in self.app.ap_rows()}
        for mac in macs:
            if mac not in aps or aps[mac]['management_state']!='managed': raise ValueError('所选 AP 包含未接管或离线设备')
        done=[]
        for mac in macs:
            ap=aps[mac]
            try: self.app.confirm_action(ap['ip'],'admission',{'enable':True})
            except (ValueError,RuntimeError,OSError) as error:
                raise ValueError('接入检查下发未确认：'+ap['ip']+'；已完成 '+str(len(done))+' 台。'+str(error)) from error
            self.admission_aps[mac]={'epoch':ap.get('session_epoch')}
            if hasattr(self.app,'balance'):self.app.balance.invalidate(mac)
            self.commit(self.rules);done.append(mac)
        return {'status':'acknowledged','completed':done}

    def reconcile(self):
        now=time.monotonic()
        for ap in self.app.ap_rows():
            mac=ap['mac']
            if (mac not in self.admission_aps or ap['management_state']!='managed' or not ap.get('session_epoch')
                    or ap['session_epoch']==self.admission_aps[mac].get('epoch') or now<self.retry.get(mac,0)): continue
            self.retry[mac]=now+60
            try: self.enable_admission([mac])
            except (ValueError,RuntimeError,OSError) as error: self.app.service.log('接入检查下发失败：'+str(error))
            return True

    def change(self,macs,para):
        if not macs or len(macs)>1024 or set(para)-{'blocked','hostname'} or str(para.get('blocked')) not in ('0','1'):
            raise ValueError('无效黑名单操作')
        macs=[canonical_mac(m) for m in macs]
        if len(set(macs))!=len(macs): raise ValueError('MAC 地址重复')
        if 'hostname' in para and len(macs)!=1: raise ValueError('请逐台修改终端名称')
        rules=dict(self.rules)
        block=str(para['blocked'])=='1'
        rows={r['mac']:r for r in self.app.monitor.rows()}
        for mac in macs:
            if block: rules[mac]=self.name(para.get('hostname',rules.get(mac,rows.get(mac,{}).get('hostname',mac))))
            else: rules.pop(mac,None)
        # Admission must become active before disconnect, preventing a reconnect race.
        self.commit(rules)
        failures=[]
        if block:
            for ap in self.app.service.snapshot()['aps']:
                if ap['state']!='run' or ap.get('last_seen_seconds',999)>=90: continue
                for mac,station in ap.get('stations',{}).items():
                    if mac not in macs or time.monotonic()-station['seen']>=STA_TTL: continue
                    try: self.app.confirm_action(ap['ip'],'disconnect',{'mac':mac})
                    except (ValueError,RuntimeError,OSError) as error: failures.append(ap['ip']+' / '+mac+'：'+str(error))
        if failures: raise ValueError('黑名单已生效，但部分在线终端的断开操作未确认：'+'；'.join(failures))
        return {'saved':True,'message':'黑名单已更新'}

    def disconnect(self,macs):
        if not isinstance(macs,list) or not macs or len(macs)>128:
            raise ValueError('请选择 1–128 台在线终端')
        macs=[canonical_mac(m) for m in macs]
        if len(set(macs))!=len(macs): raise ValueError('MAC 地址重复')
        now=time.monotonic();targets={}
        for ap in self.app.service.snapshot()['aps']:
            if ap['state']!='run' or not ap.get('secure') or ap.get('last_seen_seconds',999)>=90: continue
            for mac,station in ap.get('stations',{}).items():
                if mac in macs and now-station['seen']<STA_TTL:
                    if mac not in targets or station['seen']>targets[mac][0]:
                        targets[mac]=(station['seen'],ap['ip'])
        if set(targets)!=set(macs): raise ValueError('所选终端包含离线或未受管设备，请刷新列表')
        completed=[]
        for mac in macs:
            try: self.app.confirm_action(targets[mac][1],'disconnect',{'mac':mac})
            except (ValueError,RuntimeError,OSError) as error:
                raise ValueError('断开操作未确认：'+mac+'；已完成 '+str(len(completed))+' 台。'+str(error)) from error
            completed.append(mac)
        return {'status':'acknowledged','completed':completed}

    def csv(self,template=False):
        out=io.StringIO(newline='');writer=csv.writer(out);writer.writerow(self.fields)
        if not template:
            for mac,name in sorted(self.rules.items()):
                writer.writerow([mac,"'"+name if name.lstrip().startswith(('=','+','-','@')) else name])
        return ('\ufeff'+out.getvalue()).encode('utf8')

    def import_plan(self,text):
        if not isinstance(text,str) or len(text.encode('utf8'))>131072 or '\0' in text:
            raise ValueError('文件过大或包含无效字符')
        reader=csv.DictReader(io.StringIO(text.lstrip('\ufeff')))
        if reader.fieldnames!=list(self.fields): raise ValueError('请使用黑名单 CSV 模板')
        rows=[];seen=set()
        for row in reader:
            if len(rows)>=1024 or None in row or any(v is None for v in row.values()): raise ValueError('文件行数过多或格式错误')
            mac=canonical_mac(row[self.fields[0]])
            if mac in seen: raise ValueError('文件中存在重复 MAC：'+mac)
            seen.add(mac);rows.append({'mac':mac,'hostname':self.name(row[self.fields[1]])})
        if not rows: raise ValueError('文件没有规则')
        if len(set(self.rules)|seen)>1024: raise ValueError('黑名单最多 1024 条')
        return rows

    def import_csv(self,text):
        rows=self.import_plan(text)
        # Complete validation precedes all writes. One commit before kicking clients.
        self.commit(self.rules|{r['mac']:r['hostname'] for r in rows})
        return self.change([r['mac'] for r in rows],{'blocked':'1'})
