"""Read-only vendor 131 TDCP query, correlated outside public AP telemetry."""
import json
import struct
import re
from urllib.parse import quote,unquote
from .protocol import ProtocolError,vendor

QUERY={'method':'get','wireless':{'table':['wlan_serv','radio_entry']}}

def envelope(ident,body):
    if type(ident) is not int or not 1<=ident<=0x7fffffff: raise ValueError('invalid read request ID')
    data=json.dumps(body,separators=(',',':')).encode()
    return vendor(131,struct.pack('!IIB',ident,len(data),1)+data)

def query(ident): return envelope(ident,QUERY)

def validate_changes(changes):
    if not isinstance(changes,dict) or not changes or set(changes)-{'ssid','key'}:
        raise ValueError('仅支持修改选中服务的 SSID 和密码')
    for name,value in changes.items():
        if not isinstance(value,str) or any(ord(c)<32 or ord(c)==127 for c in value): raise ValueError('配置包含无效字符')
        if name=='ssid' and not 1<=len(value.encode('utf8'))<=32: raise ValueError('SSID 应为 1 至 32 字节')
        if name=='key' and not (8<=len(value.encode('utf8'))<=63 or len(value)==64 and re.fullmatch('[0-9a-fA-F]+',value)):
            raise ValueError('密码应为 8 至 63 字节，或 64 位十六进制 PSK')

def patch(ident,section,changes):
    if not isinstance(section,str) or not re.fullmatch(r'wlan_serv_[1-9][0-9]{0,3}',section): raise ValueError('无效 AP 服务编号')
    validate_changes(changes)
    return envelope(ident,{'method':'set','wireless':{section:{k:quote(v,safe='') for k,v in changes.items()}}})

def table(data):
    if data.get('error_code')!=0: raise ValueError('AP 拒绝配置查询，返回码 '+str(data.get('error_code','未知')))
    rows=data.get('wireless',{}).get('wlan_serv')
    if not isinstance(rows,list) or len(rows)>128: raise ValueError('AP 无线配置表格式不支持')
    result={}
    for item in rows:
        if not isinstance(item,dict) or len(item)!=1: raise ValueError('AP 无线条目格式无效')
        section,row=next(iter(item.items()))
        if not re.fullmatch(r'wlan_serv_[1-9][0-9]{0,3}',section) or section in result or not isinstance(row,dict): raise ValueError('AP 无线编号无效')
        required={'radio_id','apIdx','serv_id','ssid','enable','ssidbrd','encryption','key','vlan_id'}
        if not required<=row.keys() or str(row['serv_id'])!=section[10:]: raise ValueError('AP 无线配置不完整')
        if not 1<=int(row['radio_id'])<=31 or not 0<=int(row['apIdx'])<16: raise ValueError('AP 射频或无线编号无效')
        # TDCP values use percent encoding, including literal '%' in passwords.
        result[section]={k:unquote(v,encoding='utf8',errors='strict') if k in ('ssid','key','radius_pwd','desc') and isinstance(v,str) else v for k,v in row.items()}
    return result

def response(raw):
    if len(raw)<9: raise ProtocolError('short TDCP reply')
    ident,length,flag=struct.unpack_from('!IIB',raw)
    if flag!=0 or length!=len(raw)-9 or length>51200: raise ProtocolError('invalid TDCP reply length or flag')
    try: data=json.loads(raw[9:].rstrip(b'\0').decode('utf8'))
    except (ValueError,UnicodeError,RecursionError) as e: raise ProtocolError('invalid TDCP reply JSON') from e
    if not isinstance(data,dict): raise ProtocolError('invalid TDCP reply object')
    return ident,data
