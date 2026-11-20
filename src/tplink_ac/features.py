"""Acknowledged AP-wide controls, persisted by MAC and replayed on rejoin."""
import json
import os
import time
from .protocol import ProtocolError, vendor
from .radio import integer

DEFAULT_BAND={'enable':'off','5g_threshold':'20','dif_threshold':'4','max_fail_num':'10'}


def band_settings(value):
    if not isinstance(value,dict) or set(value)!=set(DEFAULT_BAND):
        raise ProtocolError('频谱导航参数不完整')
    if value['enable'] not in ('on','off'): raise ProtocolError('频谱导航开关无效')
    result={'enable':value['enable']}
    for field,low,high in (('5g_threshold',2,40),('dif_threshold',1,8),('max_fail_num',0,100)):
        n=integer(value[field])
        if not low<=n<=high: raise ProtocolError('频谱导航参数超出范围：'+field)
        result[field]=str(n)
    return result


def band_elements(ap,value):
    value=band_settings(value)
    bands={r.get('band') for r in ap.get('radios',[])}
    if not {'2.4 GHz','5 GHz'}<=bands: raise ProtocolError('频谱导航需要 AP 同时具有 2.4 GHz 和 5 GHz 射频')
    # band_navigation_packet_send / cw_priv_ap_spectral_assemble: four u8s.
    return vendor(58,bytes((value['enable']=='on',int(value['5g_threshold']),
                           int(value['dif_threshold']),int(value['max_fail_num']))))


class Features:
    def __init__(self,app):
        self.app=app;self.path=app.data/'ap-features.json';self.targets={};self.retry={}
        if self.path.exists():
            saved=json.loads(self.path.read_text(encoding='utf8'))
            if saved.get('version')!=1: raise ValueError('AP 功能配置版本不支持')
            self.targets=saved['band_navigation']
            for target in self.targets.values(): band_settings(target['settings'])

    def save(self):
        fd=os.open(self.path.with_suffix('.tmp'),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w',encoding='utf8') as stream:
            json.dump({'version':1,'band_navigation':self.targets},stream,ensure_ascii=False)
            stream.flush();os.fsync(stream.fileno())
        os.replace(self.path.with_suffix('.tmp'),self.path)

    def view(self):
        rows=[]
        for ap in self.app.ap_rows():
            saved=self.targets.get(ap['mac'],{})
            status=saved.get('status','not_configured')
            if saved and status=='acknowledged' and saved.get('epoch')!=ap.get('session_epoch'): status='waiting_rejoin'
            rows.append({'mac':ap['mac'],'ip':ap['ip'],'name':ap['entry_name'],
                'online':ap['management_state']=='managed','status':status,
                'settings':saved.get('settings'),
                'supported':{'2.4 GHz','5 GHz'}<={r.get('band') for r in ap.get('radios',[])}})
        return {'settings':dict(DEFAULT_BAND),'aps':rows}

    def change(self,macs,settings):
        settings=band_settings(settings)
        if not isinstance(macs,list) or not macs or len(macs)>64 or len(set(macs))!=len(macs):
            raise ValueError('请选择需要下发的 AP')
        aps={a['mac']:a for a in self.app.ap_rows()};work=[]
        for mac in macs:
            ap=aps.get(mac)
            if not ap or ap['management_state']!='managed': raise ValueError('所选 AP 包含离线设备，请刷新后重试')
            band_elements(ap,settings);work.append(ap)
        completed=[]
        for ap in work:
            try: self.app.confirm_action(ap['ip'],'band_navigation',settings)
            except (ValueError,RuntimeError,OSError) as error:
                raise ValueError('下发失败：'+ap['ip']+'；已完成 '+str(len(completed))+' 台。'+str(error)) from error
            self.targets[ap['mac']]={'settings':dict(settings),'epoch':ap.get('session_epoch'),
                                    'status':'acknowledged'}
            self.save();completed.append(ap['mac'])
        return {'status':'acknowledged','completed':completed}

    def reconcile(self):
        now=time.monotonic()
        for ap in self.app.ap_rows():
            saved=self.targets.get(ap['mac'])
            if (not saved or ap['management_state']!='managed' or not ap.get('session_epoch')
                    or saved.get('epoch')==ap['session_epoch'] or now<self.retry.get(ap['mac'],0)): continue
            self.retry[ap['mac']]=now+60
            try: self.change([ap['mac']],saved['settings'])
            except (ValueError,RuntimeError,OSError) as error:
                saved['status']='retry_failed';self.save();self.app.service.log(str(error))
            return True
