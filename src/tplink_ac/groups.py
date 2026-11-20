"""Controller-owned AP groups. Membership is keyed by MAC, never by IP."""
import copy
import ipaddress
import json
import os
import re


class Groups:
    DEFAULT = '1'  # Preserve IDs used by the first deployed controller.

    def __init__(self, app):
        self.app = app
        self.path = app.data / 'groups.json'
        self.state = {'version':1, 'next_id':2, 'groups':{
            '1':{'name':'默认分组','strategy_enable':'off','specific_strategy':'ip_range',
                 'start_ip':'','end_ip':''}}, 'members':{}}
        if self.path.exists():
            self.state = json.loads(self.path.read_text(encoding='utf8'))
            if self.state.get('version') != 1 or self.DEFAULT not in self.state['groups']:
                raise ValueError('AP 分组文件格式不支持')

    def save(self, state):
        temporary = self.path.with_suffix('.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf8') as stream:
            json.dump(state, stream, ensure_ascii=False)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, self.path)
        self.state = state

    def group_for(self, ap):
        explicit = self.state['members'].get(ap.get('mac'))
        if explicit in self.state['groups']: return explicit
        try: address = ipaddress.IPv4Address(ap['ip'])
        except (ValueError, KeyError): return self.DEFAULT
        for ident, group in self.state['groups'].items():
            if (group['strategy_enable']=='on' and
                ipaddress.IPv4Address(group['start_ip']) <= address <= ipaddress.IPv4Address(group['end_ip'])):
                return ident
        return self.DEFAULT

    def name(self, ident):
        return self.state['groups'].get(ident,self.state['groups'][self.DEFAULT])['name']

    def rows(self):
        aps = self.app.ap_rows()
        result = []
        for ident, group in self.state['groups'].items():
            members = [a for a in aps if a['group_id']==ident]
            result.append(group | {'id':ident,'group_id':ident,
                'total':str(len(members)), 'ap_num':str(len(members)),
                'active':str(sum(a['management_state']=='managed' for a in members)), 'temp_num':'0'})
        return result

    def mutate(self, method, request):
        state = copy.deepcopy(self.state)
        ids = self.app.filter_ids(request,'group_id')
        if method=='delete':
            if not ids or any(i not in state['groups'] for i in ids): raise ValueError('未找到指定分组')
            if self.DEFAULT in ids: raise ValueError('默认分组不能删除')
            if any(a['group_id'] in ids for a in self.app.ap_rows()) or any(i in ids for i in state['members'].values()):
                raise ValueError('请先将分组中的 AP 移出再删除')
            for ident in ids: del state['groups'][ident]
        elif method in ('add','set'):
            para = request.get('para',{})
            if not isinstance(para,dict) or set(para)-{'name','strategy_enable','specific_strategy','start_ip','end_ip'}:
                raise ValueError('无效 AP 分组字段')
            if method=='add':
                if len(state['groups'])>=200: raise ValueError('最多 200 个 AP 分组')
                ident = str(state['next_id']);state['next_id']+=1
                group = {'name':'','strategy_enable':'off','specific_strategy':'ip_range','start_ip':'','end_ip':''}
            else:
                if len(ids)!=1 or ids[0] not in state['groups']: raise ValueError('请选择一个分组')
                ident=ids[0];group=dict(state['groups'][ident])
            group.update(para)
            name=group['name']
            if not isinstance(name,str) or not 1<=len(name.encode('utf8'))<=32 or not name.strip() or any(ord(c)<32 for c in name):
                raise ValueError('分组名称需为 1–32 字节，不能含控制字符')
            if any(g['name']==name for i,g in state['groups'].items() if i!=ident): raise ValueError('分组名称已存在')
            if group['strategy_enable'] not in ('on','off') or group['specific_strategy']!='ip_range':
                raise ValueError('无效自动分组策略')
            if ident==self.DEFAULT and group['strategy_enable']=='on': raise ValueError('默认分组不设置地址范围')
            if group['strategy_enable']=='on':
                try:
                    lo,hi=ipaddress.IPv4Address(group['start_ip']),ipaddress.IPv4Address(group['end_ip'])
                except (ValueError,TypeError): raise ValueError('自动分组需填写有效 IPv4 地址范围')
                if hi<lo or lo.is_unspecified or hi.is_multicast or int(hi)==0xffffffff: raise ValueError('无效自动分组地址范围')
                for i,g in state['groups'].items():
                    if i!=ident and g['strategy_enable']=='on' and not (hi<ipaddress.IPv4Address(g['start_ip']) or lo>ipaddress.IPv4Address(g['end_ip'])):
                        raise ValueError('自动分组地址范围与其他分组重叠')
            state['groups'][ident]=group
        else: raise ValueError('不支持的分组操作')
        self.save(state)
        return {'apmng_set':{'name':['group_list_'+ident]}} if method=='add' else {}

    def assign(self, aps, ident):
        ident=str(ident)
        if ident not in self.state['groups']: raise ValueError('目标分组不存在')
        state=copy.deepcopy(self.state)
        for ap in aps:
            mac=ap.get('mac','')
            if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac): raise ValueError('尚未读取 AP MAC 地址')
            state['members'][mac]=ident
        self.save(state)
