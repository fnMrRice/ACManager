"""Radio settings backed by AP reports and acknowledged CAPWAP changes."""
import json
import csv
import io
import os
import re
import struct
import time
from .protocol import ProtocolError, tlv


def radio_elements(ap, profile):
    if not isinstance(profile, dict) or set(profile)-{'radio','channel','power_dbm','rf_state'}:
        raise ProtocolError('无效射频设置字段')
    radio=integer(profile.get('radio',0))
    if radio not in ap.get('radio_ids',[]): raise ProtocolError('AP 未声明该射频')
    caps=next((r for r in ap.get('radios',[]) if r['id']==radio),{})
    body=b''
    state=profile.get('rf_state',ap.get('radio_states',{}).get(str(radio)))
    if any(k in profile for k in ('channel','power_dbm')) and state!='on':
        raise ProtocolError('修改信道或功率时，请选择开启射频')
    if state=='on' or 'rf_state' in profile:
        if state not in ('on','off'): raise ProtocolError('无效射频开关')
        # Original AC always prefixes live radio configuration with admin=1.
        # 155 ACKs an isolated channel element but does not apply it.
        body+=tlv(31,bytes((radio,1 if state=='on' else 2)))
    if 'channel' in profile:
        channel=integer(profile['channel'])
        channels=allowed_channels(caps)
        if channel not in channels: raise ProtocolError('信道不在该射频的支持范围内')
        # rdmngr_wtp_pkt_send / cw_80211_direct_sequence_control_assemble.
        body+=tlv(1028,struct.pack('!BBBBI',radio,0,channel,2,0))
    if 'power_dbm' in profile:
        power=integer(profile['power_dbm'])
        lo,hi=caps.get('min_power'),caps.get('max_power')
        if lo is None or hi is None or not lo<=power<=hi:
            raise ProtocolError('功率超出 AP 上报的范围')
        body+=tlv(1041,struct.pack('!BBH',radio,0,power))
    if set(profile)=={'radio'} or not body: raise ProtocolError('没有待修改的射频参数')
    return body


def integer(value):
    if isinstance(value,bool) or not re.fullmatch(r'-?\d+',str(value)): raise ProtocolError('射频参数必须是整数')
    return int(value)


def allowed_channels(caps):
    advertised=caps.get('mutex_channels','')
    if advertised:
        try: return sorted({int(n) for n in advertised.split(',') if 1<=int(n)<=196})
        except ValueError: return []
    # Original CN firmware channel table for the 2.4 GHz band.
    return list(range(1,14)) if caps.get('band')=='2.4 GHz' else []


class Radios:
    CSV_FIELDS=('AP MAC','射频编号','信道','功率(dBm)','射频开关')
    def __init__(self, app):
        self.app=app
        self.path=app.data/'radios.json'
        self.settings=json.loads(self.path.read_text(encoding='utf8')) if self.path.exists() else {}

    def save(self):
        temp=self.path.with_suffix('.tmp')
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w',encoding='utf8') as f:
            json.dump(self.settings,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(temp,self.path);self.path.chmod(0o600)

    def csv(self):
        out=io.StringIO(newline='')
        writer=csv.writer(out);writer.writerow(self.CSV_FIELDS)
        for r in self.rows():
            writer.writerow([r['mac'],r['radio'],r['channel'] if r['channel']!='---' else '',
                r['power_dbm'] if r['power_dbm'] is not None else '',
                r['rf_state'] if r['rf_state'] in ('on','off') else ''])
        return ('\ufeff'+out.getvalue()).encode('utf8')

    def import_plan(self, text):
        if not isinstance(text,str) or len(text)>65536 or '\0' in text: raise ValueError('CSV 文件格式或大小无效')
        reader=csv.DictReader(io.StringIO(text.lstrip('\ufeff')))
        if reader.fieldnames!=list(self.CSV_FIELDS): raise ValueError('请使用导出的射频 CSV 表头，空白参数表示保持不变')
        by_key={(r['mac'],r['radio']):r for r in self.rows()}
        plan=[];seen=set()
        for number,row in enumerate(reader,2):
            if number>129: raise ValueError('一次最多导入 128 个射频')
            if None in row or None in row.values(): raise ValueError('CSV 第 '+str(number)+' 行列数不正确')
            mac=row['AP MAC'].strip().lower().replace('-',':')
            radio=integer(row['射频编号'].strip())
            key=(mac,radio)
            if key in seen: raise ValueError('CSV 包含重复射频')
            seen.add(key)
            target=by_key.get(key)
            if not target: raise ValueError('未找到 CSV 第 '+str(number)+' 行的 AP 射频')
            changes={}
            for label,field in (('信道','channel'),('功率(dBm)','power_dbm'),('射频开关','rf_state')):
                value=row[label].strip()
                if value: changes[field]=value if field=='rf_state' else integer(value)
            if not changes: continue
            ap=self.app.wireless.target({'mac':mac})
            radio_elements(ap,{'radio':radio}|changes)
            plan.append({'rf_id':target['rf_id'],'mac':mac,'radio':radio,'ap_name':target['ap_name'],
                         'ip':target['ip'],'changes':changes})
        if not plan: raise ValueError('CSV 没有待修改的参数')
        return plan

    def import_csv(self,text):
        plan=self.import_plan(text)
        completed=[]
        for item in plan:
            try: self.change([item['rf_id']],item['changes'])
            except (ValueError,RuntimeError,OSError) as error:
                raise ValueError(str(error)+'；本次导入已确认 '+str(len(completed))+' 项，后续项目未执行') from error
            completed.append(item['rf_id'])
        return {'status':'acknowledged','completed':completed}

    def rows(self):
        rows=[]
        for ap in self.app.ap_rows():
            for radio in ap['radio_ids']:
                caps=next((r for r in ap['radios'] if r['id']==radio),{})
                stats=ap.get('radio_statistics',{}).get(str(radio),{})
                saved=self.settings.get(ap['mac'],{}).get(str(radio),{})
                fresh=ap['management_state']=='managed' and time.monotonic()-ap.get('radio_report_time',0)<100
                ident=str(int(ap['entry_id'])*16+radio)
                rows.append({'id':ident,'rf_id':ident,'_row_id':ident,'mac':ap['mac'],'ip':ap['ip'],
                    'radio':radio,'ap_name':ap['ap_name'],'model_name':ap['model_name'],'ap_type':'ap',
                    'group_id':ap['group_id'],'group_name':ap['group_name'],'ap_role':'normal',
                    'ap_status':'1' if ap['management_state']=='managed' else '2','active':'1',
                    'freq_name':caps.get('band','未知').replace(' ',''),'freq_unit':str(radio),'rf_name':str(radio),
                    'radio_func_type':str(caps.get('function_type',0)),
                    'mode':'unknown','channel':str(stats.get('channel','---')) if fresh else '---',
                    'bandwidth':str(stats.get('bandwidth','unknown')) if fresh else 'unknown',
                    'power':'---','power_dbm':saved.get('power_dbm'),
                    'reported_power':stats.get('tx_power') if fresh else None,
                    'max_usr':'---','rf_max_usr':str(caps.get('max_stations','')),
                    'rf_state':ap.get('radio_states',{}).get(str(radio),'unknown') if fresh else 'unknown',
                    'channel_load':stats.get('channel_load') if fresh else None,
                    'noise':stats.get('noise') if fresh else None,
                    'channels':allowed_channels(caps),'min_power':caps.get('min_power'),'max_power':caps.get('max_power'),
                    'configuration':saved,'online':ap['management_state']=='managed',
                    'supp11ac':str(caps.get('support_ac',0)),'supp11ax':str(caps.get('support_ax',0)),
                    'supp11be':str(caps.get('support_be',0)),'supp160_m':str(caps.get('support_160',0)),
                    'supp240_m':str(caps.get('support_240',0)),'mutex_channel':caps.get('mutex_channels','')})
        return rows

    def change(self, ids, changes):
        if not ids or len(ids)>128 or len(ids)!=len(set(ids)): raise ValueError('请选择射频')
        selected={r['rf_id']:r for r in self.rows()}
        aps={a['mac']:a for a in self.app.ap_rows()}
        work=[]
        # Validate the entire selection before the first transmission.
        for ident in ids:
            row=selected.get(str(ident))
            if not row: raise ValueError('未找到射频')
            ap=self.app.wireless.target({'mac':row['mac']})
            para={'radio':row['radio']}|changes
            radio_elements(aps[row['mac']],para)
            work.append((row,ap,para))
        completed=[]
        for row,ap,para in work:
            try:
                self.app.confirm_action(ap['ip'],'radio',para)
                if 'channel' in changes:
                    deadline=time.monotonic()+30
                    while time.monotonic()<deadline:
                        current=next((a for a in self.app.ap_rows() if a['mac']==ap['mac']),{})
                        actual=current.get('radio_statistics',{}).get(str(row['radio']),{}).get('channel')
                        if actual==integer(changes['channel']) and current.get('radio_report_time',0)>ap.get('radio_report_time',0): break
                        time.sleep(.2)
                    else: raise ValueError('AP 已接收指令，但实时信道尚未变为目标值，请刷新检查')
            except (ValueError,RuntimeError,OSError) as error:
                raise ValueError('射频 '+row['rf_id']+' 修改未确认：'+str(error)+
                                 ('；已确认：'+','.join(completed) if completed else '')) from error
            saved=self.settings.setdefault(ap['mac'],{}).setdefault(str(row['radio']),{})
            saved.update(changes)
            self.save();completed.append(row['rf_id'])
        return {'status':'acknowledged','message':'AP 已确认射频配置','completed':completed}
