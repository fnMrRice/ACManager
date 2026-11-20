"""Shared services adopted from AP readback, with no implicit AP writes."""
import json
import os
import time

ORIGIN='ap_readback'

def is_imported(profile): return profile.get('_origin')==ORIGIN

def identity(row):
    fields=['ssid','key','encryption','auth','cipher']
    if str(row.get('encryption'))=='2':
        fields+=['radius_ip','radius_port','radius_pwd','radius_acct_port']
    return {k:str(row.get(k,'')) for k in fields}

def validate(profile):
    if not isinstance(profile.get('ssid'),str) or not isinstance(profile.get('key'),str):
        raise ValueError('AP 回读服务缺少名称或密码')
    if str(profile.get('encryption')) not in ('0','1','2','3'):
        raise ValueError('AP 回读服务安全模式不支持')

class ImportedServices:
    def __init__(self,wireless):
        self.wireless=wireless;self.app=wireless.app;self.suspended=False

    def sync(self,ap,rows):
        if self.suspended:return
        app=self.app;mac=ap['mac'];seen=set()
        for row in rows.values():validate(row)
        for section,row in rows.items():
            radio=int(row['radio_id']);wlan=int(row['apIdx'])+1
            rid=str(int(ap['entry_id'])*256+radio)
            slot=[(ref,b) for ref,b in app.bindings.items() if b['mac']==mac and b['radio']==radio and b['wlan']==wlan]
            if any(not b.get('imported') and (b.get('active') or b.get('desired')) for _,b in slot):continue
            old=next(((ref,b) for ref,b in slot if b.get('imported') and b.get('section')==section),None)
            candidates=sorted((sid for sid,p in app.profiles.items() if is_imported(p) and identity(p)==identity(row)
                        and ((sid,rid) not in app.bindings or (old and (sid,rid)==old[0]))),key=int)
            if candidates:sid=candidates[0]
            elif old and sum(ref[0]==old[0][0] for ref in app.bindings)==1:sid=old[0][0]
            else:sid=str(max([int(x) for x in app.profiles] or [0])+1)
            if sid not in app.profiles or identity(app.profiles[sid])!=identity(row):
                app.profiles[sid]=identity(row)|{'serv_id':sid,'_origin':ORIGIN,'enable':row['enable'],
                                                'desc':row.get('desc',''),'auto_bind':'off'}
            ref=(sid,rid);seen.add(ref)
            if old and old[0]!=ref:del app.bindings[old[0]]
            app.bindings[ref]={'mac':mac,'radio':radio,'wlan':wlan,'vlan':int(row['vlan_id']),
                'section':section,'imported':True,'active':True,'desired':False,'status':'observed',
                'confirmed_session':ap.get('session_epoch',''),'observed':dict(row)}
        app.bindings={ref:b for ref,b in app.bindings.items() if not (b.get('imported') and b['mac']==mac and ref not in seen)}
        bound={sid for sid,_ in app.bindings}
        app.profiles={sid:p for sid,p in app.profiles.items() if not is_imported(p) or sid in bound}
        self.wireless.save()

    def edit(self,ident,changes,revision):
        from .readback import validate_changes
        validate_changes(changes)
        w=self.wireless;app=self.app;current=w.profile(ident)
        if current['revision']!=revision:raise ValueError('服务或射频绑定已变化，请重新读取')
        profile=app.profiles[ident]
        if 'key' in changes and profile['encryption'] not in ('1','3'):raise ValueError('此服务不使用个人无线密码')
        changes={k:v for k,v in changes.items() if profile[k]!=v}
        if not changes:return {'saved':True,'changed':False,'message':'没有修改，未下发配置'}
        bindings=[dict(b) for (sid,_),b in app.bindings.items() if sid==ident]
        tables={};aps={};completed=[]
        self.suspended=True
        try:
            # Preflight every member before the first write, including offline APs.
            for b in bindings:
                mac=b['mac'];aps[mac]=w.target(b)
                if mac not in tables:
                    w.read_ap(mac);tables[mac]={k:dict(v) for k,v in w.read_cache[mac]['rows'].items()}
                row=tables[mac].get(b['section'])
                if row!=b['observed']:raise ValueError('AP 当前配置与已登记绑定不同，请重新同步后修改')
                if 'ssid' in changes and any(k!=b['section'] and r['radio_id']==row['radio_id'] and r['ssid']==changes['ssid'] for k,r in tables[mac].items()):
                    raise ValueError('目标射频已有同名 SSID，未覆盖其他服务')
            backup=app.data/'wireless-backups';backup.mkdir(mode=0o700,exist_ok=True)
            fd=os.open(backup/(str(time.time_ns())+'-shared.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w',encoding='utf8') as f:json.dump({'serv_id':ident,'tables':tables},f,ensure_ascii=False)
            for b in bindings:
                mac=b['mac']
                if w.target(b).get('session_epoch')!=aps[mac].get('session_epoch'):raise ValueError('AP 会话已变化')
                result=w.exchange(mac,'wireless_patch',{'section':b['section'],'changes':changes})
                if result.get('error_code')!=0:raise ValueError('AP 拒绝修改')
                w.read_ap(mac)
                tables[mac][b['section']].update(changes)
                if w.read_cache[mac]['rows']!=tables[mac]:raise ValueError('AP 回读与预期不一致，原配置已备份')
                completed.append(aps[mac]['ip']+' / 射频 '+str(b['radio']))
            profile.update(changes)
        except (ValueError,RuntimeError,OSError) as error:
            # Read actual state after a failed/ambiguous ACK, never retry a write.
            for mac in aps:
                try:w.read_ap(mac)
                except (ValueError,RuntimeError,OSError):pass
            suffix='；已确认更新：'+', '.join(completed) if completed else '；尚无已确认更新的绑定'
            raise ValueError(str(error)+suffix+'。请刷新核对各 AP，未自动重复下发') from error
        finally:
            self.suspended=False
            for mac,ap in aps.items():
                if mac in w.read_cache and w.read_cache[mac]['epoch']==ap.get('session_epoch'):
                    self.sync(ap,w.read_cache[mac]['rows'])
        return {'saved':True,'changed':True,'verified':True,'message':'已逐个回读确认 '+str(len(completed))+' 个射频，其他配置保持不变'}
