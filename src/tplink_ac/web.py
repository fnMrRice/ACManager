"""Original firmware SLP5 adapter, with optional authenticated LAN hosting."""
import json
import html
import mimetypes
import os
from pathlib import Path
import re
import secrets
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlsplit, unquote, parse_qs
from .service import Service, DEFAULTS, validate_config
from .protocol import ProtocolError
from .adoption import permitted

class Unsupported(ValueError):
    pass

def snake(key): return re.sub(r'(?<!^)(?=[A-Z])','_',key).lower()
def normalize(value):
    if isinstance(value,dict): return {snake(k):normalize(v) for k,v in value.items()}
    if isinstance(value,list): return [normalize(v) for v in value]
    return value

class Application:
    def __init__(self, root, data):
        self.root,self.data = Path(root),Path(data)
        self.data.mkdir(parents=True,exist_ok=True)
        self.service,self.lock = Service(),threading.RLock()
        self.token = secrets.token_hex(24)
        self.profiles,self.requests = {},[]
        self.page_sizes,self.bindings = {},{}
        self.ids,self.next_id = {},1
        self.config = dict(DEFAULTS)
        path = self.data/'settings.json'
        if path.is_file():
            try: self.config = validate_config(json.loads(path.read_text(encoding='utf8')))
            except (ValueError,OSError): pass
        from .wireless import Wireless
        self.wireless=Wireless(self)
        from .groups import Groups
        self.groups=Groups(self)
        from .radio import Radios
        self.radios=Radios(self)
        from .monitor import Monitor
        self.monitor=Monitor(self)
        from .station_policy import StationPolicy
        self.station_policy=StationPolicy(self)
        from .features import Features
        self.features=Features(self)
        from .edca import Edca
        self.edca=Edca(self)
        from .balance import Balance
        self.balance=Balance(self)
        self.balance.sync()
        self.maintenance_stop=threading.Event()
        self.maintenance_thread=None
        # Starting the application does not start an AC on the LAN.

    def ap_rows(self):
        with self.lock: return self._ap_rows()

    def _ap_rows(self):
        rows = []
        ids_changed=False
        # Discovery retries can change the AP's UDP source port. Display only
        # the newest session per identity, rather than duplicate table IDs.
        latest = {}
        for ap in self.service.snapshot()['aps']:
            key = ap.get('mac',ap['ip'])
            if key not in latest or ap['last_seen_seconds'] < latest[key]['last_seen_seconds']:
                latest[key] = ap
        for ap in latest.values():
            recent = ap['last_seen_seconds'] < 90
            managed = recent and ap['state']=='run'
            metadata=self.config.get('ap_metadata',{}).get(ap.get('mac'),{})
            admitted=permitted(self.config,ap['ip'],ap.get('mac'))
            managed=managed and admitted
            state = 'managed' if managed else 'discovered' if recent else 'offline'
            key = ap.get('mac',ap['ip'])
            if key not in self.ids:
                self.ids[key] = self.next_id; self.next_id += 1
                ids_changed=True
            ident = str(self.ids[key])
            name=metadata.get('name') or ap.get('mac',ap['ip'])
            group_id=self.groups.group_for(ap)
            stations=[s for s in ap.get('stations',{}).values() if time.monotonic()-s['seen']<100]
            client_count=str(len(stations)) if managed and 'station_report_time' in ap else '---'
            radio_entries=[]
            radio_fresh=managed and time.monotonic()-ap.get('radio_report_time',0)<100
            for radio in ap.get('radios',[]):
                stats=ap.get('radio_statistics',{}).get(str(radio['id']),{}) if radio_fresh else {}
                radio_entries.append({'freq_name':radio['band'].replace(' ',''),'freq_unit':str(radio['id']),
                    'channel':str(stats.get('channel',-1)),
                    'channel_load':str(stats['channel_load'])+'%' if 'channel_load' in stats else '-1',
                    'rf_client_num':str(sum(s['radio']==radio['id'] for s in stations)) if client_count!='---' else '---'})
            rows.append({'entry_id':ident,'id':ident,'entry_name':name,
                         'ap_name':name,'mac':ap.get('mac',''),'remark':metadata.get('remark',''),
                         'adoption':metadata.get('adoption','default'),'admission_allowed':admitted,
                         'ip':ap['ip'],'ip_addr':ap['ip'],'ipaddr':ap['ip'],
                         'model_name':ap.get('model_name',ap.get('model_id','未知型号')),'model_id':ap.get('model_id',''),
                         'group_id':group_id,'group_name':self.groups.name(group_id),'ap_role':'normal','entry_type':'ap',
                         'ap_status':'1' if managed else '0',
                         # Vendor UI treats every value other than "2" as online.
                         'link_status':'1' if managed else '2',
                         'management_state':state,
                         'management_label':('不接管' if metadata.get('adoption')=='block' else {'managed':'已接管','discovered':'已发现，待接管','offline':'离线'}[state]),
                         'status':ap['state'],'led':ap.get('led','-1'),
                         'led_status':{'1':'1','0':'2'}.get(str(ap.get('led')),'0'),
                         'client_num':client_count,'sta_num':client_count,'rf_entry':radio_entries,
                         'software_version':'未读取','hardware_version':ap.get('hardware_version','未读取'),
                         'software_ver':'未读取','hardware_ver':ap.get('hardware_version','未读取'),
                         'radio_ids':ap.get('radio_ids',[]),'last_operation':ap.get('last_operation'),
                         'radios':ap.get('radios',[]),'reported_wlans':ap.get('reported_wlans'),
                         'radio_statistics':ap.get('radio_statistics',{}),'radio_report_time':ap.get('radio_report_time',0),
                         'radio_states':ap.get('radio_states',{}),'reported_bssids':ap.get('reported_bssids',{}),
                         'wlan_report_time':ap.get('wlan_report_time',0),
                         'session_epoch':ap.get('session_epoch',''),
                         'association_requests':ap.get('association_requests',0),'association_denials':ap.get('association_denials',0),
                         'wireless_dialect':ap.get('wireless_dialect','auto'),
                         '_experimental':True})
        if ids_changed: self.wireless.save()
        return rows

    def start_maintenance(self):
        if self.maintenance_thread and self.maintenance_thread.is_alive(): return
        self.maintenance_stop.clear()
        def run():
            while not self.maintenance_stop.wait(5):
                if not self.service.running or not self.lock.acquire(blocking=False): continue
                try:
                    if not self.wireless.auto_import() and not self.wireless.reconcile() and not self.station_policy.reconcile() and not self.features.reconcile() and not self.edca.reconcile():
                        self.balance.reconcile()
                except (ValueError,RuntimeError,OSError) as error:
                    self.service.log('无线配置核对失败：'+str(error))
                finally: self.lock.release()
        self.maintenance_thread=threading.Thread(target=run,daemon=True,name='ac-maintenance')
        self.maintenance_thread.start()

    def stop_maintenance(self):
        self.maintenance_stop.set()
        if self.maintenance_thread: self.maintenance_thread.join(timeout=15)

    def table(self, rows, name, request):
        # Vendor's format_tbl_arry_with_secname_id uses [{table_ID:{...}}].
        filters = request.get('filter',[])
        if isinstance(filters,dict): filters=[filters]
        def matches(row, filt):
            for key,value in filt.items():
                if value is None or value=='' or value==[]: continue
                values = value if isinstance(value,list) else [value]
                values=[str(v) for v in values]
                if key=='group_id' and '-1' in values: continue
                if key=='status' and name=='ap_list':
                    if ('2' if row['management_state']=='managed' else '0') not in values: return False
                    continue
                if key in ('hostname','name','entry_name','ap_name','ssid'):
                    if not any(v.casefold() in str(row.get(key,'')).casefold() for v in values): return False
                elif key in ('entry_id','group_id','ip','mac','serv_id','radio_id','bind_status','blocked',
                             'online_status','data_type','freq_name','auth_type','entry_type','ap_role','rf_id','ap_status','active'):
                    if str(row.get(key,'')) not in values: return False
            return True
        if filters: rows=[r for r in rows if any(matches(r,f) for f in filters)]
        total = len(rows)
        index = request.get('index',request.get('para',{}))
        if isinstance(index,dict) and 'start' in index:
            start = max(0,int(index['start']))
            rows = rows[start:max(start,int(index.get('end',total-1))+1)]
        return [{name+'_'+str(r.get('_row_id',r.get('entry_id',r.get('serv_id',r.get('id',i+1))))):r} for i,r in enumerate(rows)],total

    def get_value(self,module,name):
        if module=='apmng_balance' and name=='rule_list':return self.balance.rows()
        if module=='apmng_rf' and name=='edca_rule': return self.edca.rows()
        if module=='apmng_rf' and name=='rf_entry': return self.radios.rows()
        if module=='apmng_rf' and name=='rf_entry_capability': return {}
        if module=='host_management' and name=='host_info': return self.monitor.rows()
        if module=='host_management' and name=='host_info_backup_status': return {'status':'1'}
        if module=='system' and name=='sys': return self.monitor.controller_info()
        if module=='apmng_mesh' and name=='re_node_list': return []
        if module=='global_config' and name=='page_size': return self.page_sizes
        if module in ('apmng_status','apmng_set') and name=='ap_list': return self.ap_rows()
        if module=='apmng_set' and name=='group_list':
            return self.groups.rows()
        if module=='apmng_set' and name=='model_list':
            models = {r['model_id']: {'id':r['model_id'],'model_name':r['model_name'],'device_status':'accessed'}
                      for r in self.ap_rows() if r['model_id']}
            return list(models.values())
        if module=='apmng_set' and name=='ap_list_capability': return {}
        if module=='apmng_set' and name=='authorize_ap_list':
            # This is the vendor's pending Mesh authorization queue, not the
            # controller transport allowlist. The UI hides these rows from
            # the AP status table. Discovery alone does not create this queue.
            return []
        if module=='apmng_status' and name=='ap_link_status':
            rows = self.ap_rows()
            online = sum(r['link_status']=='1' for r in rows)
            discovered = sum(r['management_state']=='discovered' for r in rows)
            return {'online_num':str(online),'offline_num':str(len(rows)-online-discovered),'discovered_num':str(discovered)}
        if module=='apmng_mesh' and name=='settings': return {'enable':'off'}
        if (module,name) in (('authentication','portal_auth_ssid_bind_list'),('vlan','vlan_pool')): return []
        if module=='apmng_status' and name=='online_model_list': return []
        if module=='apmng_set' and name=='settings':
            return {'apmngr_status':'on' if self.service.running and self.config['enabled'] else 'off',
                    'ap_max':'64','auto_auth':'off'}
        if module=='apmng_wserv' and name=='wlan_serv': return self.wireless.service_rows()
        if module=='apmng_wserv' and name=='radio_bind_list': return self.radio_rows()
        if module=='apmng_wserv' and name=='settings': return {'enable':'on'}
        if module=='apmng_wserv' and name=='wserv_switch_rule': return []
        if module=='apmng_status' and name=='ap_ssid_list': return self.ssid_rows()
        if module=='time_mngt' and name=='time_obj': return []
        if module=='authentication' and name=='portal': return {'auth_mode':'none','enable':'off'}
        if module=='authentication' and name=='portal_auth_list': return []
        if module=='system' and name=='user_level': return {'level':'sys_admin'}
        if module=='system' and name=='service_port': return {'http_port':str(getattr(self,'web_port',8765)),'https_port':'0','web_timeout':'30'}
        if module=='system' and name=='chassis_name': return {'chassis_name':'TP-LINK AP'}
        if module=='system' and name=='cfg_status': return {'status':'Saved'}
        if module=='system' and name=='system_log':
            return [{'id':str(i+1),'time':e['time'],'content':e['message'],'level':'info'} for i,e in enumerate(self.service.snapshot()['events'])]
        if (module,name) in (('ha_mngt','batch_sync_status'),('apmng_rrm','rrm_status'),('apmng_upgrade','upgrade_status')):
            return {'status':'0','supported':False}
        if module=='apmng_set_status' and name=='status': return {'ap_full_flag':'0'}
        if module=='system' and name=='device_info':
            return {'model':'TP-LINK AP','hardware_version':'PC','firmware_version':'0.1.0','device_name':self.config['name']}
        if module=='device_info' and name in ('info','dual_band'):
            return {'device_model':'TP-LINK AP','hw_version':'PC','sw_version':'0.1.0','dev_name':self.config['name']}
        if module=='cloud_config' and name=='new_firmware': return {'fw_new_notify':'0'}
        if name=='capability': return {}
        raise Unsupported('尚未实现原版接口：get '+module+'.'+name)

    def ds(self, body):
        body = normalize(body)
        method = body.get('method','get')
        modules = [(m,v) for m,v in body.items() if m not in ('method','params')]
        with self.lock:
            self.requests.append({'time':time.strftime('%H:%M:%S'),'method':method,
                                  'modules':{m:{'keys':list(v),'target':v.get('name',v.get('table'))} if isinstance(v,dict) else {} for m,v in modules}})
            self.requests = self.requests[-200:]
            result = {'error_code':0}
            if method=='get':
                for module,request in modules:
                    if not isinstance(request,dict): raise ValueError('invalid request')
                    names = request.get('table',request.get('name',[]))
                    if isinstance(names,str): names=[names]
                    out = {}
                    for name in names:
                        value = self.get_value(module,name)
                        if isinstance(value,list):
                            value,count = self.table(value,name,request)
                            out[name+'_count'] = count
                            out.setdefault('count',{})[name] = count
                        out[name] = value
                    result[module] = out
                return result
            if method=='do' and len(modules)==1 and modules[0][0]=='user_management':
                if 'get_encrypt_info' in modules[0][1]: return result | {'encrypt_type':['0']}
            # Mutations are deliberately atomic and limited to one operation.
            # Unknown commands never get a synthetic success response.
            if len(modules)!=1: raise Unsupported('不支持批量写入；请逐项操作')
            module,request = modules[0]
            if module=='apmng_balance' and request.get('table')=='rule_list':
                return result | self.balance.mutate(method,request)
            if module=='host_management' and method=='do' and set(request)=={'disconnect'}:
                return result | self.station_policy.disconnect(request['disconnect'].get('mac_list'))
            if module=='apmng_status' and method=='do' and set(request) in ({'ap_reboot'},{'ap_reset'}):
                from .ap_management import control
                name=next(iter(request))
                return result | control(self,request[name].get('entry_id',[]),'reboot' if name=='ap_reboot' else 'factory_reset')
            if module=='apmng_rf' and method=='set' and request.get('table')=='rf_entry':
                return result | self.radios.change(self.filter_ids(request,'rf_id'),request.get('para',{}))
            if module=='apmng_set' and request.get('table')=='group_list':
                return result | self.groups.mutate(method,request)
            if module=='host_management' and method=='set' and request.get('table')=='host_info':
                para=request.get('para',{})
                if 'blocked' in para:
                    return result | self.station_policy.change(self.filter_ids(request,'mac'),para)
                if set(para)!={'hostname'}:
                    raise Unsupported('此接口支持终端名称和黑名单')
                macs=self.filter_ids(request,'mac')
                if len(macs)!=1: raise ValueError('请逐台修改终端名称')
                self.monitor.rename(macs[0],para['hostname'])
                return result
            if module=='global_config' and method=='set' and set(request)=={'page_size'}:
                values = request['page_size']
                if not isinstance(values,dict) or any(str(v) not in ('10','20','50','100','200','500','1000') for v in values.values()):
                    raise ValueError('无效分页大小')
                self.page_sizes.update(values)
                return result
            if module in ('apmng_status','apmng_set') and method=='set' and request.get('table')=='ap_list':
                para = request.get('para',{})
                ids = self.filter_ids(request,'entry_id')
                rows = [r for r in self.ap_rows() if r['entry_id'] in ids]
                if len(rows)!=len(ids) or not rows: raise ValueError('未找到指定 AP')
                if set(para)=={'group_id'}:
                    self.groups.assign(rows,para['group_id'])
                    return result
                if set(para)=={'led_status'} and str(para['led_status']) in ('0','1'):
                    from .ap_management import control
                    return result | control(self,ids,'led_on' if str(para['led_status'])=='1' else 'led_off')
                # Name and metadata edits remain single-device operations.
                if len(rows)!=1: raise Unsupported('请逐台操作 AP')
                if para and set(para)<={'entry_name','ap_name','remark','adoption'}:
                    changes={('name' if k in ('entry_name','ap_name') else k):v for k,v in para.items()}
                    return result | self.save_ap_settings({'mac':rows[0]['mac']}|changes)
                if set(para)!={'led_status'} or str(para['led_status']) not in ('0','1'):
                    raise Unsupported('此页面支持 AP 名称、备注、接管策略和 LED 开关')
                pending = self.service.action(rows[0]['ip'],'led_on' if str(para['led_status'])=='1' else 'led_off')
                return result | pending | {'message':'指令已发送，等待 AP 确认；请在结果日志查看状态'}
            if module=='apmng_wserv' and method=='set' and request.get('table')=='radio_bind_list':
                return result | self.bind_radio(request)
            if module=='apmng_wserv' and method=='add':
                table = request.get('table','wlan_serv')
                if table!='wlan_serv': raise Unsupported('尚未实现 '+table)
                profile = request.get('para') or request.get('wlan_serv')
                if not isinstance(profile,dict): raise ValueError('无线服务缺少 para')
                self.validate_profile(profile)
                if len(self.profiles)>=16: raise ValueError('最多 16 个无线服务')
                ident = str(max([int(x) for x in self.profiles] or [0])+1)
                self.profiles[ident] = profile | {'serv_id':ident,'_deployment':'local_only'}
                self.wireless.save()
                return result | {'apmng_wserv':{'name':'wlan_serv_'+ident},
                                 'local_only':True,'message':'无线服务已保存；请在射频绑定页选择 AP 下发'}
            if module=='apmng_wserv' and method in ('set','delete') and request.get('table')=='wlan_serv':
                ids = self.filter_ids(request,'serv_id')
                if any(i.startswith('ap_') or self.profiles.get(i,{}).get('_origin')=='ap_readback' for i in ids):
                    raise ValueError('AP 原有服务请通过该行的“查看 / 修改”操作；未执行批量启停或删除')
                if not ids or any(i not in self.profiles for i in ids): raise ValueError('未找到无线服务')
                if len(ids)!=1: raise Unsupported('请逐项修改无线服务，等待 AP 确认后再操作下一项')
                changed = {}
                for ident in ids:
                    if method=='set':
                        p = self.profiles[ident] | request.get('para',{})
                        self.validate_profile(p); changed[ident] = p | {'serv_id':ident}
                for ident in ids: self.wireless.change(ident,changed.get(ident))
                return result | {'message':'无线服务已'+('删除' if method=='delete' else '更新')}
            raise Unsupported('尚未实现原版写入：'+method+' '+module+' '+','.join(request))

    @staticmethod
    def filter_ids(request,key):
        filters = request.get('filter',[])
        if isinstance(filters,dict): filters=[filters]
        ids = []
        for f in filters:
            value = f.get(key,[])
            ids.extend(str(x) for x in (value if isinstance(value,list) else [value]))
        return list(dict.fromkeys(ids))

    def radio_rows(self):
        rows = []
        operations = self.service.snapshot().get('operations',{})
        for ap in self.ap_rows():
            if ap['management_state']!='managed' or not permitted(self.config,ap['ip'],ap['mac']): continue
            for radio in ap['radio_ids']:
                rid = str(int(ap['entry_id'])*256+radio)
                for sid in self.profiles:
                    bind = self.bindings.get((sid,rid),{})
                    result = operations.get(bind.get('id'))
                    if result and bind.get('status') in ('pending','unconfirmed'): bind['status']=result['status']
                    detail=next((r for r in ap['radios'] if r['id']==radio),{})
                    rows.append({'id':sid+'_'+rid,'_row_id':sid+'_'+rid,'serv_id':sid,'radio_id':rid,'entry_id':ap['entry_id'],
                                 'ap_name':ap['entry_name'],'group_id':ap['group_id'],'group_name':ap['group_name'],
                                 'freq_unit':str(radio),'freq_band':detail.get('band','---'),'freq_name':detail.get('band','射频 '+str(radio)),
                                 'freq_mode':'unknown','ap_type':ap['model_name'],
                                 'bind_status':'1' if bind.get('active') else '0',
                                 'bind_vlan_type':'single_vlan','vlan_id':str(bind.get('vlan',0)),
                                 'imported':self.profiles[sid].get('_origin')=='ap_readback',
                                 'wlan_id':str(bind.get('wlan','')),
                                 '_deployment':bind.get('status','unbound')})
        return rows

    def ssid_rows(self):
        rows=[]
        for ap in self.ap_rows():
            cached=self.wireless.read_cache.get(ap['mac'])
            if cached and cached['epoch']==ap.get('session_epoch'):
                for section,item in cached['rows'].items():
                    radio=int(item['radio_id']);slot=int(item['apIdx'])+1
                    owner=next((sid for (sid,_),b in self.bindings.items() if b['mac']==ap['mac'] and b['radio']==radio and b['wlan']==slot and b.get('active')),None)
                    detail=next((r for r in ap['radios'] if r['id']==radio),{})
                    rows.append({'entry_id':ap['entry_id'],'_row_id':ap['entry_id']+'_read_'+section,
                                 'serv_id':owner,'source':'ap_readback','source_label':'AP 回读','editable':False,
                                 'password_state':'开放网络' if str(item['encryption'])=='0' else '已读取',
                                 'freq_name':detail.get('band','射频 '+str(radio)),'ssid':item['ssid'],
                                 'desc':item.get('desc',''),'vlan_id':str(item['vlan_id']),'bind_vlan_type':'single_vlan',
                                 'encryption':{'0':'开放网络','1':'WPA-PSK / WPA2-PSK','2':'WPA / WPA2','3':'WPA2-PSK / WPA3-SAE'}.get(str(item['encryption']),'未识别'),
                                 'status':'1' if ap['management_state']=='managed' and item['enable']=='on' else '0'})
                continue
            seen=set()
            for (sid,_),binding in self.bindings.items():
                if binding['mac']!=ap['mac']: continue
                profile=self.profiles[sid];radio=binding['radio'];seen.add((radio,profile['ssid']))
                if not binding.get('active'): continue
                detail=next((r for r in ap['radios'] if r['id']==radio),{})
                rows.append({'entry_id':ap['entry_id'],'_row_id':ap['entry_id']+'_'+sid+'_'+str(radio),
                             'serv_id':sid,'source':'controller_saved','source_label':'本控制器保存','editable':binding.get('status')!='slot_conflict',
                             'password_state':'已保存' if str(profile.get('encryption','1'))!='0' else '开放网络',
                             'freq_name':detail.get('band','射频 '+str(radio)),'ssid':profile['ssid'],
                             'desc':profile.get('desc',''),'vlan_id':str(binding['vlan']),
                             'bind_vlan_type':'single_vlan','encryption':('开放网络' if str(profile.get('encryption','1'))=='0' else
                                 {'1':'WPA-PSK','2':'WPA2-PSK','3':'WPA/WPA2-PSK'}.get(str(profile.get('auth','2')),'PSK')+' / '+
                                 {'0':'自动','1':'TKIP','2':'AES'}.get(str(profile.get('cipher','2')),'未知')),
                             'status':'1' if ap['management_state']=='managed' else '0'})
            for index,item in enumerate(ap.get('reported_wlans') or []):
                if (item['radio'],item['ssid']) in seen: continue
                rows.append({'entry_id':ap['entry_id'],'_row_id':ap['entry_id']+'_reported_'+str(index),
                             'serv_id':None,'source':'ap_report','source_label':'AP 上报','editable':False,'password_state':'未读取',
                             'freq_name':'射频 '+str(item['radio']),'ssid':item['ssid'],
                             'desc':'AP 上报的已有服务','vlan_id':'---','bind_vlan_type':'single_vlan',
                             'encryption':'未读取','status':'1' if ap['management_state']=='managed' else '0'})
        return rows

    def bind_radio(self,request):
        return self.wireless.bind(request)

    def validate_profile(self,p):
        from .protocol import wlan_elements
        if str(p.get('encryption','1')) not in ('0','1'):
            raise Unsupported('已实现开放网络及 WPA/WPA2-PSK；企业认证、WPA3 和 PPSK 尚未适配')
        for flag in ('bw_ctrl_enable','time_switch','central_forward_switch'):
            if str(p.get(flag,'off')) not in ('off','0'): raise Unsupported('当前不支持 '+flag)
        if str(p.get('auto_bind','off')) not in ('off','0'): raise Unsupported('请关闭自动绑定，并在射频绑定页选择要管理的 AP')
        if str(p.get('mlo_switch','0'))!='0': raise Unsupported('当前不支持 MLO')
        for flag,default in (('enable','on'),('ssidbrd','1'),('isolate','0')):
            allowed=('on','off') if flag=='enable' else ('0','1')
            if str(p.get(flag,default)) not in allowed: raise ValueError('无效无线开关：'+flag)
        wlan_elements(str(p.get('ssid','')),str(p.get('key','')),vlan=int(p.get('default_bind_vlan',0) or 0),
                      encryption=p.get('encryption','1'),auth=p.get('auth','2'),cipher=p.get('cipher','2'),
                      key_interval=p.get('key_update_intv','86400') or '86400')

    def api(self,path,body):
        if path=='wireless/read-ap':
            with self.lock: return self.wireless.read_ap(body.get('mac'))
        if path=='wireless/edit-ap':
            with self.lock: return self.wireless.edit_ap(body)
        if path=='wireless/inventory':
            with self.lock: return self.wireless.inventory(body.get('entry_id'))
        if path=='wireless/profile':
            with self.lock: return self.wireless.profile(body.get('serv_id'))
        if path=='wireless/edit':
            with self.lock: return self.wireless.edit(body)
        if path=='wireless/bind-preview':
            with self.lock: return self.wireless.bind(normalize(body['request']),preview=True)
        if path=='wireless/bind':
            if not isinstance(body.get('revision'),str): raise ValueError('请先预览目标 AP')
            with self.lock: return self.wireless.bind(normalize(body['request']),expected=body['revision'])
        if path=='terminals/disconnect':
            with self.lock: return self.station_policy.disconnect(body.get('macs'))
        if path=='blacklist/status':
            with self.lock: return {'aps':self.station_policy.admission_status()}
        if path=='blacklist/enable-admission':
            with self.lock: return self.station_policy.enable_admission(body.get('macs'))
        if path=='edca':
            from .edca import DEFAULTS
            with self.lock: return {'rules':self.edca.rows(),'defaults':DEFAULTS,'radios':self.radios.rows()}
        if path=='edca/save':
            with self.lock: return self.edca.change(body)
        if path=='edca/delete':
            with self.lock: return self.edca.delete(body.get('ids'))
        if path=='features/band-navigation':
            with self.lock: return self.features.view()
        if path=='features/band-navigation/save':
            with self.lock: return self.features.change(body.get('macs'),body.get('settings'))
        if path=='blacklist/import-preview':
            with self.lock: return {'items':self.station_policy.import_plan(body.get('csv'))}
        if path=='blacklist/import':
            with self.lock: return self.station_policy.import_csv(body.get('csv'))
        if path=='radios':
            with self.lock: return {'radios':self.radios.rows()}
        if path=='radios/save':
            with self.lock: return self.radios.change(body.get('ids',[]),body.get('changes',{}))
        if path=='radios/import-preview':
            with self.lock: return {'items':self.radios.import_plan(body.get('csv'))}
        if path=='radios/import':
            with self.lock: return self.radios.import_csv(body.get('csv'))
        if path=='topology':
            with self.lock: return self.monitor.topology(body.get('dev_type','all'))
        if path=='ap-settings':
            return {'auto_adopt':self.config['auto_adopt'],'adopt_subnets':self.config['adopt_subnets'],
                    'aps':self.ap_rows()}
        if path=='ap-settings/save': return self.save_ap_settings(body)
        if path=='status': return self.service.snapshot() | {'requests':self.requests[-30:]}
        if path=='config': return self.config
        if path=='save':
            if self.service.running: raise ValueError('请先停止服务')
            cfg = validate_config(self.config | body)
            path = self.data/'settings.json'
            path.write_text(json.dumps(cfg,ensure_ascii=False,indent=2),encoding='utf8')
            self.config = cfg
            return {'saved':True}
        if path=='start': return self.service.start(self.config)
        if path=='stop': self.service.stop(); return {'stopped':True}
        if path=='action':
            if body['action'] in ('reboot','factory_reset'):
                from .ap_management import control
                rows=[a for a in self.ap_rows() if a['ip']==body['ip'] and a['management_state']=='managed']
                if len(rows)!=1: raise ValueError('未找到唯一的受管 AP')
                with self.lock: return control(self,[rows[0]['entry_id']],body['action'])
            return self.service.action(body['ip'],body['action'],body.get('profile'))
        if path=='certificates':
            from .certificates import generate
            result = generate(self.data/'certificates')
            self.config.update(result)
            return result
        raise Unsupported('未实现 API '+path)

    def confirm_action(self, ip, action, profile=None):
        pending=self.service.action(ip,action,profile)
        deadline=time.monotonic()+12
        while time.monotonic()<deadline:
            result=self.service.snapshot().get('operations',{}).get(pending['id'],{})
            status=result.get('status','pending')
            if status!='pending':
                if status!='acknowledged':
                    raise ValueError('AP 应答：'+status+'，返回码 '+str(result.get('result_code','未知')))
                return result
            time.sleep(.05)
        raise ValueError('等待 AP 应答超时')

    def save_ap_settings(self,body):
        with self.lock:
            if not body or set(body)-{'auto_adopt','adopt_subnets','mac','name','remark','adoption'}: raise ValueError('无效 AP 设置')
            cfg=json.loads(json.dumps(self.config))
            for key in ('auto_adopt','adopt_subnets'):
                if key in body: cfg[key]=body[key]
            if 'mac' in body:
                mac=body['mac']
                rows=[r for r in self.ap_rows() if r['mac']==mac]
                if not rows and mac not in cfg['ap_metadata']: raise ValueError('未发现该 AP')
                item=cfg['ap_metadata'].setdefault(mac,{})
                item.update({k:body[k] for k in ('name','remark','adoption') if k in body})
            elif any(k in body for k in ('name','remark','adoption')): raise ValueError('需要指定 AP')
            cfg=validate_config(cfg)
            path=self.data/'settings.json';temporary=path.with_suffix('.tmp')
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
            with os.fdopen(fd,'w',encoding='utf8') as stream:
                json.dump(cfg,stream,ensure_ascii=False,indent=2);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,path);path.chmod(0o600)
            self.config=cfg;self.service.update_policy(cfg)
            self.wireless.save()
            return {'saved':True,'message':'设置已保存并生效'}

class Server(ThreadingHTTPServer):
    daemon_threads = True
    # Linux needs SO_REUSEADDR to restart while closed HTTP connections are
    # in TIME_WAIT. Windows uses different reuse semantics; keep exclusive
    # ownership there. Never enable SO_REUSEPORT.
    allow_reuse_address = os.name != 'nt'

    def server_bind(self):
        # Numeric loopback listener needs no DNS lookup (or optional IDNA
        # codec package on minimal OpenWrt Python installations).
        from socketserver import TCPServer
        TCPServer.server_bind(self)
        self.server_name,self.server_port = self.server_address[:2]

def create_server(app,port=8765,listen='127.0.0.1',auth=None):
    import ipaddress
    address = ipaddress.ip_address(listen)
    if address.version != 4 or address.is_unspecified:
        raise ValueError('网页服务需绑定具体 IPv4 地址')
    if not address.is_loopback and auth is None:
        raise ValueError('局域网网页服务必须设置用户名和密码')
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def send_bytes(self,data,content_type,status=200,extra=None):
            self.send_response(status)
            self.send_header('Content-Type',content_type)
            self.send_header('Content-Length',str(len(data)))
            self.send_header('Cache-Control',(extra or {}).get('Cache-Control',
                'no-store' if content_type.startswith(('text/html','application/json')) else 'private, max-age=3600'))
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Referrer-Policy','no-referrer')
            self.send_header('X-Frame-Options','SAMEORIGIN')
            for key,value in (extra or {}).items():
                if key!='Cache-Control': self.send_header(key,value)
            self.end_headers(); self.wfile.write(data)
        def json(self,value,status=200): self.send_bytes(json.dumps(value,ensure_ascii=False).encode('utf8'),'application/json; charset=utf-8',status)
        def check_host(self):
            names = {listen}
            if address.is_loopback: names.add('localhost')
            return self.headers.get('Host') in {n+':'+str(self.server.server_port) for n in names}
        def access_token(self):
            return auth.token(self.headers.get('Cookie')) if auth else app.token
        def do_GET(self):
            if not self.check_host(): return self.json({'error':'invalid host'},403)
            path = unquote(urlsplit(self.path).path)
            token = self.access_token()
            if auth and path=='/login':
                return self.send_bytes((app.root/'login.html').read_bytes(),'text/html; charset=utf-8')
            if not token:
                if path.startswith(('/api/','/stok=')): return self.json({'error':'请先登录'},401)
                return self.send_bytes(b'', 'text/html', 302, {'Location':'/login'})
            if path in ('/','/ac'):
                file = app.root/'web-static/index.html'
                if not file.is_file(): return self.json({'error':'缺少固件网页资源，请先运行 prepare_assets.py'},503)
                text = file.read_text(encoding='utf8')
                text = text.replace('<title>TL-AC100</title>','<title>TP-LINK AP</title>').replace('random=20260817190248','random=ac-ui-7')
                boot = '<base href="/"><script>sessionStorage.setItem("stok",'+json.dumps(token)+');localStorage.setItem("_tid_",'+json.dumps(token)+');localStorage.setItem("usrLvl","sys_admin");window.acLoginRequired='+json.dumps(auth is not None)+';</script><script src="/bridge.js"></script>'
                boot = boot.replace('src="/bridge.js"','src="/bridge.js?v=9"')
                boot += '<script src="/ap-list.js?v=7"></script>'
                boot += '<script src="/monitor.js?v=1"></script>'
                boot += '<script src="/radio.js?v=1"></script>'
                boot += '<script src="/features.js?v=1"></script>'
                boot += '<script src="/edca.js?v=1"></script>'
                boot += '<script src="/wireless.js?v=4"></script>'
                boot += '<style>.t-header__logo,.t-header__tp-logo{display:none!important}.t-header__left{padding-left:20px}</style>'
                text = text.replace('<head>','<head>'+boot,1)
                return self.send_bytes(text.encode('utf8'),'text/html; charset=utf-8')
            if path=='/setup':
                text = (app.root/'setup.html').read_text(encoding='utf8').replace('__TOKEN__',token)
                return self.send_bytes(text.encode('utf8'),'text/html; charset=utf-8')
            if path=='/aps':
                return self.send_bytes(b'','text/html',302,{'Location':'/#/systemState/homeApStatus'})
            if path=='/api/status':
                if self.headers.get('X-AC-Token')!=token: return self.json({'error':'unauthorized'},403)
                return self.json(app.api('status',{}))
            if path=='/health': return self.json({'application':'tplink-ac-lab','version':'0.1.0'})
            if path=='/stok='+token+'/admin/host_management/host_info_backup':
                with app.lock: data=app.monitor.csv()
                return self.send_bytes(data,'text/csv; charset=utf-8',extra={
                    'Content-Disposition':'attachment; filename="terminals.csv"','Cache-Control':'no-store'})
            if path in ('/stok='+token+'/admin/host_management/sta_blacklist_backup',
                        '/stok='+token+'/admin/host_management/export_blacklist_template'):
                with app.lock: data=app.station_policy.csv(template=path.endswith('export_blacklist_template'))
                return self.send_bytes(data,'text/csv; charset=utf-8',extra={
                    'Content-Disposition':'attachment; filename="blacklist.csv"','Cache-Control':'no-store'})
            if path=='/stok='+token+'/admin/apmng_rf/backup_rf':
                with app.lock: data=app.radios.csv()
                return self.send_bytes(data,'text/csv; charset=utf-8',extra={
                    'Content-Disposition':'attachment; filename="radios.csv"','Cache-Control':'no-store'})
            if path=='/stok='+token+'/admin/apmng_status/export_ap_list':
                from .ap_management import export_csv
                with app.lock: data=export_csv(app)
                return self.send_bytes(data,'text/csv; charset=utf-8',extra={
                    'Content-Disposition':'attachment; filename="aps.csv"','Cache-Control':'no-store'})
            if not path.startswith('/web-static/') and path not in ('/bridge.js','/ap-list.js','/monitor.js','/radio.js','/features.js','/edca.js','/wireless.js','/navigation.json'): return self.json({'error':'not found'},404)
            file = (app.root/path.lstrip('/')).resolve()
            if not file.is_relative_to(app.root.resolve()) or not file.is_file(): return self.json({'error':'not found'},404)
            override = (app.root/'overrides'/path.removeprefix('/web-static/')).resolve()
            if path.startswith('/web-static/') and override.is_relative_to((app.root/'overrides').resolve()) and override.is_file():
                file = override
            return self.send_bytes(file.read_bytes(),mimetypes.guess_type(file.name)[0] or 'application/octet-stream',
                                   extra={'Cache-Control':'no-store'} if file.suffix=='.js' else None)
        def do_POST(self):
            if not self.check_host(): return self.json({'error':'invalid host'},403)
            path = urlsplit(self.path).path
            router_login = auth is not None and path=='/login/luci'
            origin = self.headers.get('Origin')
            if router_login:
                # LuCI is on another port of this router. Allow only its host;
                # credentials still pass the normal verifier and rate limit.
                try:
                    source = urlsplit(origin or '')
                    valid_origin = (source.scheme in ('http','https') and source.hostname==listen
                                    and not source.username and not source.password
                                    and not source.path and not source.query and not source.fragment)
                    source.port  # Validate a malformed port before accepting.
                except ValueError: valid_origin = False
                if not valid_origin: return self.json({'error':'cross-origin denied'},403)
            elif origin and origin!='http://'+self.headers.get('Host',''):
                return self.json({'error':'cross-origin denied'},403)
            token = self.access_token()
            login = auth is not None and path in ('/login','/login/luci')
            if not token and not login: return self.json({'error':'请先登录'},401)
            is_ds = token is not None and path=='/stok='+token+'/ds'
            bootstrap = path=='/'
            if not login and not is_ds and not bootstrap and self.headers.get('X-AC-Token')!=token: return self.json({'error':'unauthorized'},403)
            try:
                size = int(self.headers.get('Content-Length','0'))
                if not 0<size<=65536: raise ValueError('请求长度超限')
                payload = self.rfile.read(size)
                if router_login:
                    if self.headers.get('Content-Type','').split(';')[0]!='application/x-www-form-urlencoded':
                        raise ValueError('需要登录表单')
                    values = parse_qs(payload.decode('utf8'),keep_blank_values=True,max_num_fields=2,strict_parsing=True)
                    if set(values)!={'username','password'} or any(len(v)!=1 for v in values.values()):
                        raise ValueError('登录表单无效')
                    body = {k:v[0] for k,v in values.items()}
                else: body = json.loads(payload)
                if not isinstance(body,dict): raise ValueError('请求必须是 JSON 对象')
                if login:
                    if not router_login and self.headers.get('Content-Type','').split(';')[0]!='application/json':
                        return self.json({'error':'需要 JSON 请求'},400)
                    sid = auth.login(body.get('username'),body.get('password'),self.client_address[0])
                    if not sid:
                        if router_login: return self.login_error('自动登录失败，请检查插件中保存的用户名和密码，或在此重新登录。',401)
                        return self.json({'error':'用户名或密码错误'},401)
                    if router_login:
                        return self.send_bytes(b'','text/html',303,{'Location':'/#/systemState/homeApStatus',
                            'Set-Cookie':'ac_session='+sid+'; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200'})
                    return self.send_bytes(b'{"ok":true}','application/json',extra={'Set-Cookie':'ac_session='+sid+'; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200'})
                if path=='/api/logout' and auth:
                    auth.logout(self.headers.get('Cookie'))
                    return self.send_bytes(b'{"ok":true}','application/json',extra={'Set-Cookie':'ac_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'})
                if bootstrap:
                    if normalize(body)=={'method':'do','user_management':{'get_encrypt_info':None}}:
                        return self.json({'error_code':0,'encrypt_type':['0']})
                    return self.json({'error':'unsupported bootstrap request'},403)
                if is_ds:
                    if normalize(body)=={'method':'do','system':{'logout':'null'}} and auth:
                        auth.logout(self.headers.get('Cookie'))
                        return self.send_bytes(b'{"error_code":0,"logged_out":true}','application/json',extra={'Set-Cookie':'ac_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'})
                    try: result = app.ds(body)
                    except (ValueError,KeyError,RuntimeError,TypeError) as e:
                        result = {'error_code':99999,'error_msg':str(e),'implemented':False}
                    return self.json(result)
                if path=='/api/shutdown':
                    self.json({'stopped':True})
                    threading.Thread(target=self.server.shutdown,daemon=True).start()
                    return
                if not path.startswith('/api/'): raise Unsupported('unknown route')
                return self.json(app.api(path[5:],body))
            except (ValueError,KeyError,RuntimeError,OSError,TypeError) as e:
                if router_login: return self.login_error(str(e),400)
                return self.json({'error':str(e)},400)
        def login_error(self, message, status):
            page = (app.root/'login.html').read_text(encoding='utf8')
            page = page.replace('<p id="error" role="alert"></p>',
                                '<p id="error" role="alert">'+html.escape(message)+'</p>')
            return self.send_bytes(page.encode('utf8'),'text/html; charset=utf-8',status)
    server = Server((listen,port),Handler)
    app.web_port = server.server_port
    return server
