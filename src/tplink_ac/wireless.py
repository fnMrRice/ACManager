"""Persistent wireless-service ownership and AP-confirmed operations."""
import json
import hashlib
import secrets
import os
import time
from .adoption import permitted
from .imported import ImportedServices,is_imported,validate as validate_imported

class Wireless:
    def __init__(self,app):
        self.app=app
        self.path=app.data/'wireless.json'
        self.retry_after={}
        self.read_cache={}
        # Observed AP configurations are not desired-state deployment profiles.
        # Importing them must never enroll them in automatic apply/remove.
        self.observed_path=app.data/'wireless-observed.json'
        self.observed={}
        self.observe_after={}
        self.observe_epoch={}
        self.observe_attempt_epoch={}
        if self.observed_path.exists():
            state=json.loads(self.observed_path.read_text(encoding='utf8'))
            if state.get('version')!=1: raise ValueError('AP 无线回读记录版本不支持')
            self.observed=state['aps']
        if self.path.exists():
            state=json.loads(self.path.read_text(encoding='utf8'))
            if state.get('version')!=1: raise ValueError('无线配置文件版本不支持')
            for profile in state['profiles'].values():
                if is_imported(profile):validate_imported(profile)
                else:app.validate_profile(profile)
            app.profiles=state['profiles']
            app.bindings={tuple(row['ref']):row['value'] for row in state['bindings']}
            for binding in app.bindings.values():
                binding.setdefault('desired',binding.get('active',False))
            app.ids=state.get('ap_ids',{})
            app.next_id=max(app.ids.values(),default=0)+1
        self.imported=ImportedServices(self)

    def save(self):
        app=self.app
        state={'version':1,'profiles':app.profiles,'ap_ids':app.ids,
               'bindings':[{'ref':list(k),'value':v} for k,v in app.bindings.items()]}
        temporary=self.path.with_suffix('.tmp')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w',encoding='utf8') as f:
            json.dump(state,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(temporary,self.path);self.path.chmod(0o600)

    @staticmethod
    def digest(value):
        return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()

    def remember(self,ap,rows):
        record={'rows':rows,'ip':ap['ip'],'name':ap['ap_name'],'read_at':int(time.time())}
        self.observed[ap['mac']]=record
        temporary=self.observed_path.with_suffix('.tmp')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w',encoding='utf8') as f:
            json.dump({'version':1,'aps':self.observed},f,ensure_ascii=False)
            f.flush();os.fsync(f.fileno())
        os.replace(temporary,self.observed_path);self.observed_path.chmod(0o600)
        self.observe_epoch[ap['mac']]=ap.get('session_epoch')
        self.observe_attempt_epoch[ap['mac']]=ap.get('session_epoch')
        self.observe_after[ap['mac']]=time.monotonic()+300
        self.imported.sync(ap,rows)

    def auto_import(self):
        """Read at most one AP per maintenance pass; never send a setting."""
        now=time.monotonic()
        for ap in self.app.ap_rows():
            mac=ap['mac']
            if ap['management_state']!='managed' or not ap.get('session_epoch'): continue
            same_epoch=self.observe_attempt_epoch.get(mac)==ap['session_epoch']
            due=self.observe_after.get(mac,0)
            if now<due and same_epoch: continue
            self.observe_after[mac]=now+300
            self.observe_attempt_epoch[mac]=ap['session_epoch']
            try: self.read_ap(mac)
            except (ValueError,RuntimeError,OSError) as error:
                self.app.service.log('AP 原有无线服务读取失败 '+mac+'：'+str(error))
            return True
        return False

    def service_rows(self):
        """Shared imported profiles and real radio bindings, without list keys."""
        aps={a['mac']:a for a in self.app.ap_rows()}
        rows=[]
        for sid,p in self.app.profiles.items():
            if not is_imported(p):
                rows.append(dict(p,source='controller_saved',source_label='本控制器创建'));continue
            bindings=[b for (ident,_),b in self.app.bindings.items() if ident==sid]
            current=all(aps.get(b['mac'],{}).get('management_state')=='managed'
                        and self.observe_epoch.get(b['mac'])==aps.get(b['mac'],{}).get('session_epoch')
                        and time.time()-self.observed.get(b['mac'],{}).get('read_at',0)<600 for b in bindings)
            rows.append({'serv_id':sid,'ssid':p['ssid'],'desc':p.get('desc',''),'enable':p['enable'],
                         'encryption':'4' if p['encryption']=='3' else p['encryption'],
                         'source':'ap_import','source_label':'AP 回读合并' if current else 'AP 回读合并（含历史记录）',
                         'binding_label':str(len({b['mac'] for b in bindings}))+' 台 AP / '+str(len(bindings))+' 个射频',
                         'auto_bind':'off','default_bind_freq':[],'default_bind_vlan':'0','bind_vlan_type':'single_vlan'})
        return rows

    def inventory(self,entry_id=None):
        """Observe reported names; never infer a key or WLAN ID from row order."""
        aps={a['entry_id']:a for a in self.app.ap_rows()}
        rows=[]
        for row in self.app.ssid_rows():
            if entry_id is not None and row['entry_id']!=str(entry_id): continue
            ap=aps[row['entry_id']]
            rows.append(row | {'mac':ap['mac'],'ip':ap['ip'],'ap_name':ap['ap_name']})
        return {'items':rows,'password_readback':True,
                'aps':[{'mac':a['mac'],'entry_id':a['entry_id'],'ip':a['ip'],'name':a['ap_name'],'online':a['management_state']=='managed'} for a in aps.values() if entry_id is None or a['entry_id']==str(entry_id)],
                'message':'可按 AP 读取现有 SSID、密码和加密配置；读取不下发修改。'}

    def exchange(self,mac,action='wireless_read',payload=None):
        ap=self.target({'mac':mac})
        ident=secrets.randbelow(0x7ffffffe)+1
        operation=self.app.service.action(ap['ip'],action,{'request_id':ident}|(payload or {}))
        deadline=time.monotonic()+15
        result=None
        while time.monotonic()<deadline:
            result=result or self.app.service.take_readback(ident)
            status=self.app.service.snapshot().get('operations',{}).get(operation['id'],{}).get('status')
            if status in ('rejected','timeout','send_failed'): raise ValueError('AP 配置读取失败：'+status)
            if result and status=='acknowledged':
                if 'error' in result: raise ValueError(result['error'])
                if self.target({'mac':mac}).get('session_epoch')!=ap.get('session_epoch'): raise ValueError('AP 会话已变化，请重新读取')
                return result['data']
            time.sleep(.05)
        raise ValueError('AP 未返回配置内容；确认应答不代表已读到配置')

    def read_ap(self,mac):
        from .readback import table
        ap=self.target({'mac':mac});rows=table(self.exchange(mac))
        epoch=ap.get('session_epoch');revision=self.digest([mac,epoch,rows])
        self.read_cache[mac]={'epoch':epoch,'rows':rows,'revision':revision}
        self.remember(ap,rows)
        items=[]
        for section,row in rows.items():
            radio=int(row['radio_id']);wlan=int(row['apIdx'])+1
            owner=[sid for (sid,_),b in self.app.bindings.items() if b['mac']==mac and b['radio']==radio and b['wlan']==wlan and (b.get('active') or b.get('desired'))]
            reason=''
            if owner:
                bindings=[b for (sid,_),b in self.app.bindings.items() if sid==owner[0] and (b.get('active') or b.get('desired'))]
                if len(bindings)>1: reason='这是共享服务，请从“无线服务”统一修改'
                else:
                    saved=self.app.profiles[owner[0]]
                    if any(str(saved.get(k,default))!=str(row.get(k)) for k,default in (('ssid',''),('key',''),('encryption','1'),('auth','2'),('cipher','2'))):
                        reason='本控制器保存的服务与 AP 当前配置不同，请先核对'
            items.append({'section':section,'radio':radio,'wlan':wlan,'ssid':row['ssid'],'key':row['key'],
                          'encryption':row['encryption'],'auth':row.get('auth'),'cipher':row.get('cipher'),
                          'vlan':row['vlan_id'],'hidden':str(row['ssidbrd'])=='0','enable':row['enable'],
                          'mlo':row.get('mlo_enable'),'editable':not reason,'reason':reason,'owner':owner[0] if owner else None})
        return {'mac':mac,'ip':ap['ip'],'ap_name':ap['ap_name'],'source':'ap_readback','items':items,'revision':revision}

    def edit_ap(self,body):
        from .readback import validate_changes
        mac=body.get('mac');section=body.get('section');changes=body.get('changes')
        validate_changes(changes)
        # Re-read before writing; never trust fields posted by a browser as the baseline.
        current=self.read_ap(mac)
        if body.get('revision')!=current['revision']: raise ValueError('AP 配置或会话已变化，请重新读取')
        item=next((r for r in current['items'] if r['section']==section),None)
        if not item or not item['editable']: raise ValueError(item['reason'] if item else 'AP 服务不存在')
        imported_owner=bool(item['owner'] and is_imported(self.app.profiles[item['owner']]))
        before=self.read_cache[mac]['rows'];old=before[section]
        if 'key' in changes and str(old['encryption']) not in ('1','3'): raise ValueError('此服务不使用个人无线密码，未更改认证方式')
        changes={k:v for k,v in changes.items() if v!=old[k]}
        if not changes:return {'saved':True,'changed':False,'message':'没有修改，未下发配置'}
        if 'ssid' in changes and any(k!=section and r['radio_id']==old['radio_id'] and r['ssid']==changes['ssid'] for k,r in before.items()): raise ValueError('同一射频已有此 SSID，未覆盖或合并其他服务')
        backup=self.app.data/'wireless-backups';backup.mkdir(mode=0o700,exist_ok=True)
        filename=backup/(str(time.time_ns())+'-'+mac.replace(':','')+'.json')
        fd=os.open(filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='utf8') as f:json.dump({'mac':mac,'section':section,'rows':before},f,ensure_ascii=False,indent=2)
        result=self.exchange(mac,'wireless_patch',{'section':section,'changes':changes})
        if result.get('error_code')!=0: raise ValueError('AP 拒绝修改，返回码 '+str(result.get('error_code','未知')))
        after=self.read_ap(mac);expected={k:dict(v) for k,v in before.items()};expected[section].update(changes)
        if self.read_cache[mac]['rows']!=expected:
            raise ValueError('AP 已处理修改，但回读与预期不一致；原配置已备份，请核对，未继续下发其他设置')
        if item['owner'] and not imported_owner:
            self.app.profiles[item['owner']].update(changes);self.save()
            # The read above ran before the controller's saved profile was
            # synchronized. Its temporary mismatch no longer applies.
            for row in after['items']:
                if row['section']==section: row.update(editable=True,reason='')
        return {'saved':True,'changed':True,'verified':True,'message':'AP 回读确认修改成功，其余无线配置保持不变','current':after}

    def profile(self,ident):
        if not isinstance(ident,str) or ident not in self.app.profiles:
            raise ValueError('原有服务尚未读取完整配置，不能修改；请选择本控制器保存的无线服务')
        p=self.app.profiles[ident]
        aps={a['mac']:a for a in self.app.ap_rows()}
        bindings=[dict(b) for (sid,_),b in self.app.bindings.items() if sid==ident]
        targets=[{'mac':b['mac'],'ip':aps.get(b['mac'],{}).get('ip','离线'),
                  'ap_name':aps.get(b['mac'],{}).get('ap_name',b['mac']),
                  'radio':b['radio'],'wlan':b['wlan'],'vlan':b['vlan']}
                 for b in bindings if b.get('desired') or b.get('active')]
        return {'profile':{k:v for k,v in p.items() if not k.startswith('_')},'source':'ap_readback' if is_imported(p) else 'controller_saved','targets':targets,
                'revision':self.digest([p,bindings])}

    def edit(self,body):
        current=self.profile(body.get('serv_id'))
        if is_imported(self.app.profiles[body['serv_id']]):
            return self.imported.edit(body['serv_id'],body.get('changes'),body.get('revision'))
        if body.get('revision')!=current['revision']: raise ValueError('配置或绑定已变化，请重新读取后修改')
        changes=body.get('changes')
        if not isinstance(changes,dict) or not changes or set(changes)-{'ssid','key'}:
            raise ValueError('此入口仅修改 SSID 和密码，其余配置保持不变')
        if any(not isinstance(v,str) for v in changes.values()): raise ValueError('SSID 和密码必须为文本')
        p=current['profile'] | changes
        self.app.validate_profile(p)
        if p==current['profile']:
            return {'saved':True,'changed':False,'message':'没有修改，未下发配置'}
        self.change(body['serv_id'],p)
        return {'saved':True,'changed':True,'message':'配置已保存，已绑定的 AP 操作已确认' if current['targets'] else '配置已保存，尚未绑定 AP'}

    def target(self,binding):
        matches=[a for a in self.app.ap_rows() if a['mac']==binding['mac']]
        if len(matches)!=1:
            raise ValueError('目标 AP 未接管或离线，请等待重新上线')
        ap=matches[0]
        if not permitted(self.app.config,ap['ip'],ap['mac']): raise ValueError('该 AP 不在允许管理列表中')
        if ap['management_state']!='managed': raise ValueError('目标 AP 未接管或离线，请等待重新上线')
        return ap

    def command(self,binding,action,profile=None):
        if binding.get('imported'):raise ValueError('AP 回读绑定不能使用删除重建流程，请在无线服务修改名称或密码')
        if binding.get('status')=='slot_conflict':
            raise ValueError('保存的无线编号已被其他服务占用，请先解除此绑定，再选择空闲射频重新绑定')
        ap=self.target(binding)
        self.read_cache.pop(binding['mac'],None)
        params={'radio':binding['radio'],'wlan':binding['wlan']}
        if action=='apply':
            params.update(ssid=profile['ssid'],key=profile.get('key',''),vlan=binding['vlan'],
                          hidden=str(profile.get('ssidbrd','1'))=='0',
                          isolate=str(profile.get('isolate','0'))=='1',dialect='auto',
                          encryption=profile.get('encryption','1'),auth=profile.get('auth','2'),
                          cipher=profile.get('cipher','2'),key_interval=profile.get('key_update_intv','86400') or '86400')
        result=self.app.service.action(ap['ip'],action,params)
        binding.update(status='pending',id=result['id'],last_action=action)
        self.save()
        deadline=time.monotonic()+12
        while time.monotonic()<deadline:
            result=self.app.service.snapshot().get('operations',{}).get(binding['id'],{})
            status=result.get('status','pending')
            if status!='pending':
                binding['status']=status
                if status=='acknowledged':
                    binding['active']=action=='apply'
                    binding['confirmed_session']=ap.get('session_epoch','')
                    if action=='apply':
                        current=self.target(binding)
                        slot=str(binding['radio'])+':'+str(binding['wlan'])
                        binding['confirmed_bssid']=current.get('reported_bssids',{}).get(slot,'')
                self.save()
                if status!='acknowledged':
                    raise ValueError('AP 未确认操作：'+status+'，返回码 '+str(result.get('result_code','未知')))
                return result
            time.sleep(.05)
        binding['status']='unconfirmed';self.save()
        raise ValueError('等待 AP 应答超时，尚未确认修改成功')

    def reconcile(self):
        """Restore owned, enabled services once per new authenticated AP session.

        Retained SSIDs are observed without rewriting their configuration.
        A reused slot is a conflict, never permission to delete an external WLAN.
        """
        now=time.monotonic()
        aps={a['mac']:a for a in self.app.ap_rows()}
        for ref,binding in self.app.bindings.items():
            if binding.get('imported'):continue
            profile=self.app.profiles.get(ref[0],{})
            ap=aps.get(binding['mac'],{})
            epoch=ap.get('session_epoch')
            if (not binding.get('desired') or profile.get('enable','on')!='on'
                    or ap.get('management_state')!='managed' or not epoch
                    or epoch==binding.get('confirmed_session')
                    or now<self.retry_after.get(ref,0)
                    or now-ap.get('radio_report_time',0)>=100): continue
            self.retry_after[ref]=now+60
            slot=str(binding['radio'])+':'+str(binding['wlan'])
            if slot in ap.get('reported_bssids',{}):
                same_name=[r for r in ap.get('reported_wlans',[]) or []
                           if r['radio']==binding['radio'] and r['ssid']==profile['ssid']]
                previous_bssid=binding.get('confirmed_bssid')
                current_bssid=ap['reported_bssids'][slot]
                # These are durable bindings created by an acknowledged write,
                # not newly discovered SSIDs. Recognition does not send a write
                # or claim that the AP reported its password/security settings.
                if (binding.get('confirmed_session') and len(same_name)==1
                        and (not previous_bssid or previous_bssid==current_bssid)):
                    binding.update(active=True,status='retained',confirmed_session=epoch,
                                   confirmed_bssid=current_bssid)
                    self.save()
                    continue
                binding.update(active=False,status='slot_conflict')
                self.save()
                continue
            binding['active']=False
            try:
                self.command(binding,'apply',profile)
                self.app.service.log('已恢复 AP '+binding['mac']+' 的已保存无线服务')
            except (ValueError,RuntimeError,OSError) as error:
                self.app.service.log('无线服务恢复失败 '+binding['mac']+'：'+str(error))
            # Keep each maintenance iteration bounded to one acknowledged action.
            return True

    def bind(self,request,preview=False,expected=None):
        app=self.app;ids=app.filter_ids(request,'serv_id');para=request.get('para',{})
        radios=para.get('radio_id',[]);vlans=para.get('vlan_id',[])
        enabled=str(para.get('bind_status'))=='1'
        if str(para.get('bind_status')) not in ('0','1') or len(ids)!=1 or not isinstance(radios,list) or not 1<=len(radios)<=8:
            raise ValueError('请选择一个无线服务和 1 至 8 个射频')
        if len(set(map(str,radios)))!=len(radios): raise ValueError('射频重复')
        if enabled and (len(vlans)!=len(radios) or para.get('bind_vlan_type','single_vlan')!='single_vlan'):
            raise ValueError('请为每个射频选择普通 VLAN')
        sid=ids[0];profile=app.profiles.get(sid)
        if not profile: raise ValueError('无线服务不存在')
        if is_imported(profile):raise ValueError('这些射频绑定由 AP 现有配置自动登记；当前可在无线服务统一修改名称或密码')
        if enabled and profile.get('enable','on')!='on': raise ValueError('请先启用无线服务')
        work=[]
        for i,rid in enumerate(map(str,radios)):
            apid,radio=divmod(int(rid),256)
            matches=[a for a in app.ap_rows() if a['entry_id']==str(apid) and radio in a['radio_ids']]
            if len(matches)!=1: raise ValueError('射频不存在')
            ap=matches[0];old=app.bindings.get((sid,rid))
            binding=dict(old) if old else {'mac':ap['mac'],'radio':radio,'active':False,'status':'unbound'}
            self.target(binding)
            if not enabled:
                if old is None: continue
            else:
                vlan=int(vlans[i])
                if not 0<=vlan<=4094: raise ValueError('VLAN 应为 0 至 4094')
                if old and old.get('active') and old['vlan']!=vlan: raise ValueError('请先解绑再修改 VLAN')
                binding['vlan']=vlan
                if not old:
                    detail=next((r for r in ap.get('radios',[]) if r['id']==radio),{})
                    limit=min(16,int(detail.get('max_ssids',0)))
                    report=ap.get('reported_wlans')
                    if not limit or report is None: raise ValueError('尚未读取 AP 无线清单和容量，请等待 AP 上报')
                    # A report has no slot IDs. Never infer occupied IDs from
                    # the number or order of external SSIDs.
                    existing=[r for r in report if r['radio']==radio]
                    if any(r['ssid']==profile['ssid'] for r in existing):
                        raise ValueError('目标射频已有同名 SSID；无法读取其完整配置，未覆盖或重复创建')
                    owned=[b for b in app.bindings.values() if b['mac']==ap['mac'] and b['radio']==radio]
                    occupied={b['wlan'] for b in owned}
                    external=[r for r in existing if not any(app.profiles[k[0]]['ssid']==r['ssid'] for k,b in app.bindings.items() if b in owned)]
                    if external:
                        if time.monotonic()-ap.get('radio_report_time',0)>=100:
                            raise ValueError('尚未收到最新无线编号上报，无法确认空闲编号')
                        reported={int(k.split(':')[1]) for k in ap.get('reported_bssids',{}) if k.split(':')[0]==str(radio)}
                        if len(reported)<len(existing): raise ValueError('无线清单与编号上报不一致，请稍后重试')
                        occupied.update(reported)
                    if len(occupied)>=limit: raise ValueError('AP 无线服务容量已满')
                    slots=[n for n in range(limit,0,-1) if n not in occupied]
                    if not slots: raise ValueError('没有可分配的无线编号')
                    binding['wlan']=slots[0]
            work.append((rid,binding))
        plan={'items':[{'radio_id':rid,'mac':b['mac'],'ip':self.target(b)['ip'],
                        'ap_name':self.target(b)['ap_name'],'radio':b['radio'],'wlan':b['wlan'],
                        'vlan':b.get('vlan',0),'action':('保持绑定' if b.get('active') else '新增到空闲编号') if enabled else '解除本服务绑定'}
                       for rid,b in work], 'ssid':profile['ssid'],'enabled':enabled}
        revision=self.digest([plan,profile,[(rid,b,self.target(b).get('session_epoch'),self.target(b).get('reported_bssids')) for rid,b in work]])
        if preview: return plan | {'revision':revision}
        if expected is not None and expected!=revision: raise ValueError('AP 状态或配置已变化，请重新预览')
        for rid,binding in work:
            app.bindings[(sid,rid)]=binding
            if enabled!=bool(binding.get('active')):
                self.command(binding,'apply' if enabled else 'remove',profile)
            binding['desired']=enabled
        self.save()
        return {'status':'acknowledged','message':'AP 已确认'+('绑定' if enabled else '解绑')}

    def change(self,ident,profile=None):
        """Change owned services only; preserve the previous profile on failure."""
        app=self.app;old=app.profiles[ident]
        if is_imported(old):raise ValueError('AP 原有共享服务请使用“SSID / 密码”，保留其他配置')
        if profile==old: return
        bindings=[b for (sid,_),b in app.bindings.items() if sid==ident and (b.get('desired') or b.get('active'))]
        for binding in bindings:
            ap=self.target(binding)
            if binding.get('status')=='slot_conflict': raise ValueError('无线编号已被其他服务占用，未下发修改')
            slot=str(binding['radio'])+':'+str(binding['wlan'])
            current=ap.get('reported_bssids',{}).get(slot)
            if current and binding.get('confirmed_bssid') and current!=binding['confirmed_bssid']:
                raise ValueError('无线编号对应的 BSSID 已变化，未下发修改')
            if profile and profile['ssid']!=old['ssid'] and any(r['radio']==binding['radio'] and r['ssid']==profile['ssid'] for r in ap.get('reported_wlans',[]) or []):
                raise ValueError('目标射频已有同名 SSID，未覆盖原有服务')
        completed=[]
        try:
            for binding in bindings:
                was_active=binding.get('active',False)
                completed.append((binding,was_active))
                if was_active: self.command(binding,'remove')
                if profile and profile.get('enable','on')=='on': self.command(binding,'apply',profile)
        except (ValueError,RuntimeError,OSError) as error:
            failures=[]
            for binding,was_active in reversed(completed):
                try:
                    if binding.get('active'): self.command(binding,'remove')
                    if was_active: self.command(binding,'apply',old)
                except (ValueError,RuntimeError,OSError) as recovery:
                    binding['status']='recovery_failed';failures.append(str(recovery))
            self.save()
            if failures: raise ValueError(str(error)+'；恢复旧配置未完成：'+'；'.join(failures)) from error
            raise
        if profile is None:
            del app.profiles[ident]
            app.bindings={k:v for k,v in app.bindings.items() if k[0]!=ident}
        else: app.profiles[ident]=profile
        self.save()
