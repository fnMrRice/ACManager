"""Static EDCA rule deployment (vendor 146), with per-radio acknowledgements."""
import json
import os
import struct
import time
from .protocol import ProtocolError, vendor
from .radio import integer

QUEUES=('ap_vo','ap_vi','ap_be','ap_bk','sta_vo','sta_vi','sta_be','sta_bk')
DEFAULTS=dict(zip(QUEUES,(
    [1,2,3,47],[1,3,4,94],[2,4,6,0],[3,4,10,0],
    [2,2,3,47],[2,3,4,94],[2,4,10,0],[3,4,10,0])))


def parameters(value):
    if not isinstance(value,dict) or set(value)!=set(QUEUES): raise ProtocolError('请填写全部八类 EDCA 队列参数')
    result={}
    for queue in QUEUES:
        row=value[queue]
        if not isinstance(row,list) or len(row)!=4: raise ProtocolError('EDCA 每类队列需要四个参数')
        aifs,lo,hi,txop=map(integer,row)
        if not 1<=aifs<=15 or not 1<=lo<=hi<=10 or not 0<=txop<=8191:
            raise ProtocolError('EDCA 参数超出范围：'+queue)
        result[queue]=[aifs,lo,hi,txop]
    return result


def elements(ap,profile):
    if not isinstance(profile,dict) or set(profile)!={'radio','enable','parameters'}: raise ProtocolError('无效 EDCA 配置')
    radio=integer(profile['radio'])
    if radio not in ap.get('radio_ids',[]): raise ProtocolError('AP 未声明该射频')
    if profile['enable'] not in ('on','off'): raise ProtocolError('无效 EDCA 开关')
    rows=parameters(profile['parameters'])
    # cw_priv_edca_set_assemble: radio, enable, eight packed BBBH rows.
    return vendor(146,bytes((radio,int(profile['enable']=='on')))+b''.join(struct.pack('!BBBH',*rows[q]) for q in QUEUES))


class Edca:
    def __init__(self,app):
        self.app=app;self.path=app.data/'edca.json';self.rules={};self.retry={}
        if self.path.exists():
            state=json.loads(self.path.read_text(encoding='utf8'))
            if state.get('version')!=1: raise ValueError('EDCA 配置版本不支持')
            self.rules=state['rules']
            for rule in self.rules.values(): parameters(rule['parameters'])

    def save(self):
        temp=self.path.with_suffix('.tmp');fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w',encoding='utf8') as stream:
            json.dump({'version':1,'rules':self.rules},stream,ensure_ascii=False)
            stream.flush();os.fsync(stream.fileno())
        os.replace(temp,self.path)

    def rows(self):
        aps={a['mac']:a for a in self.app.ap_rows()};rows=[]
        for ident,rule in self.rules.items():
            targets=[];confirmed=0
            for target in rule['targets']:
                ap=aps.get(target['mac'],{})
                state=target.get('status','pending')
                if state=='acknowledged' and target.get('epoch')!=ap.get('session_epoch'): state='waiting_rejoin'
                if ap.get('management_state')!='managed': state='offline'
                confirmed+=state=='acknowledged'
                targets.append({'mac':target['mac'],'radio':target['radio'],
                    'name':ap.get('entry_name',target['mac']),'ip':ap.get('ip',''), 'status':state})
            rows.append({'id':ident,'edca_rule_id':ident,'edca_rule_name':rule['name'],
                'target_text':'、'.join(t['name']+' / 射频 '+str(t['radio']) for t in targets),
                'deployment':str(confirmed)+'/'+str(len(targets))+' 已确认',
                'enable':rule['enable'],'targets':targets,'parameters':rule['parameters']})
        return rows

    def preflight(self,targets):
        if not isinstance(targets,list) or not 1<=len(targets)<=128: raise ValueError('请选择 1 至 128 个射频')
        aps={a['mac']:a for a in self.app.ap_rows()};work=[];seen=set()
        for target in targets:
            if not isinstance(target,dict) or not {'mac','radio'}<=set(target): raise ValueError('无效目标射频')
            key=(target['mac'],integer(target['radio']));ap=aps.get(key[0])
            if key in seen: raise ValueError('射频重复')
            seen.add(key)
            if not ap or ap['management_state']!='managed' or key[1] not in ap['radio_ids']:
                raise ValueError('所选射频包含离线或未接管设备')
            work.append((ap,key[1]))
        return work

    def deploy_one(self,rule,target,ap):
        self.app.confirm_action(ap['ip'],'edca',{'radio':target['radio'],'enable':rule['enable'],'parameters':rule['parameters']})
        target.update(status='acknowledged',epoch=ap.get('session_epoch'))
        self.save()

    def change(self,body):
        if not isinstance(body,dict) or set(body)-{'id','name','enable','targets','parameters'}: raise ValueError('无效 EDCA 规则')
        name=body.get('name','')
        if not isinstance(name,str) or not name.strip() or len(name.encode('utf8'))>64 or any(ord(c)<32 for c in name):
            raise ValueError('规则名称应为 1–64 字节')
        ident=str(body.get('id') or max(map(int,self.rules),default=0)+1)
        old=self.rules.get(ident)
        if body.get('id') and not old: raise ValueError('规则不存在')
        if not old and len(self.rules)>=64: raise ValueError('最多 64 条 EDCA 规则')
        if any(r['name']==name.strip() for i,r in self.rules.items() if i!=ident): raise ValueError('规则名称重复')
        if body.get('enable') not in ('on','off'): raise ValueError('无效 EDCA 开关')
        params=parameters(body.get('parameters'));work=self.preflight(body.get('targets'))
        keys={(a['mac'],r) for a,r in work}
        if old and keys!={(t['mac'],t['radio']) for t in old['targets']}:
            raise ValueError('修改目标射频前，请先删除原规则以恢复这些射频的默认 EDCA')
        for other_id,other in self.rules.items():
            if other_id!=ident and keys&{(t['mac'],t['radio']) for t in other['targets']}:
                raise ValueError('所选射频已属于其他 EDCA 规则')
        rule={'name':name.strip(),'enable':body['enable'],'parameters':params,
              'targets':[{'mac':a['mac'],'radio':r,'status':'pending'} for a,r in work]}
        # Persist intent first, so an interrupted deployment is visible/retryable.
        self.rules[ident]=rule;self.save();errors=[]
        for target,(ap,_) in zip(rule['targets'],work):
            try: self.deploy_one(rule,target,ap)
            except (ValueError,RuntimeError,OSError) as error:
                target.update(status='failed',error=str(error));errors.append(ap['ip']+'：'+str(error));self.save()
        if errors: raise ValueError('规则已保存，部分射频未确认；请查看下发状态：'+'；'.join(errors))
        return {'id':ident,'status':'acknowledged'}

    def delete(self,ids):
        if not isinstance(ids,list) or not ids or len(set(ids))!=len(ids) or any(str(i) not in self.rules for i in ids):
            raise ValueError('请选择存在的规则')
        work={str(i):self.preflight(self.rules[str(i)]['targets']) for i in ids}
        completed=[]
        for ident,targets in work.items():
            rule=self.rules[ident];rule['enable']='off'
            for target in rule['targets']: target.update(status='pending',epoch='')
            self.save()
            for target,(ap,_) in zip(rule['targets'],targets):
                try: self.deploy_one(rule,target,ap)
                except (ValueError,RuntimeError,OSError) as error:
                    target['status']='failed';self.save()
                    raise ValueError('规则停用尚未确认，已保留以便重试；已删除 '+str(len(completed))+' 条。'+str(error)) from error
            del self.rules[ident];self.save();completed.append(ident)
        return {'deleted':completed}

    def reconcile(self):
        now=time.monotonic();aps={a['mac']:a for a in self.app.ap_rows()}
        for ident,rule in self.rules.items():
            for target in rule['targets']:
                ap=aps.get(target['mac']);key=(ident,target['mac'],target['radio'])
                if not ap or ap['management_state']!='managed' or not ap.get('session_epoch'): continue
                if target.get('epoch')==ap['session_epoch'] and target.get('status')=='acknowledged': continue
                if now<self.retry.get(key,0): continue
                self.retry[key]=now+60
                try: self.deploy_one(rule,target,ap)
                except (ValueError,RuntimeError,OSError) as error:
                    target.update(status='failed',error=str(error));self.save();self.app.service.log('EDCA 下发失败：'+str(error))
                return True

    def forget_ap(self,mac):
        for ident in list(self.rules):
            self.rules[ident]['targets']=[t for t in self.rules[ident]['targets'] if t['mac']!=mac]
            if not self.rules[ident]['targets']: del self.rules[ident]
        self.save()
