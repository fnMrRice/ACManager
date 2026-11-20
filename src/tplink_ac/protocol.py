"""Portable bounded CAPWAP codec. Wire integers are big endian.

TP-LINK vendor 0x12345678 uses a 16-bit container ID followed by nested
type/length/value records, not the RFC's opaque vendor value alone.
"""
import struct
import time
import re
from dataclasses import dataclass

VENDOR = 0x12345678
WLAN_REQUEST, WLAN_RESPONSE = 0x0033DD01, 0x0033DD02
NAMES = {1: 'discovery_request', 2: 'discovery_response', 3: 'join_request',
         4: 'join_response', 5: 'configuration_status_request', 6: 'configuration_status_response',
         7: 'configuration_update_request', 8: 'configuration_update_response',
         9: 'wtp_event_request', 10: 'wtp_event_response', 11: 'change_state_request',
         12: 'change_state_response', 13: 'echo_request', 14: 'echo_response',
         17: 'reset_request', 18: 'reset_response', 25:'station_configuration_request',
         26:'station_configuration_response', WLAN_REQUEST: 'wlan_request',
         WLAN_RESPONSE: 'wlan_response'}

class ProtocolError(ValueError):
    pass

def tlv(kind, value):
    if not 0 <= kind <= 65535 or len(value) > 65535:
        raise ProtocolError('element too large or invalid type')
    return struct.pack('!HH', kind, len(value)) + value

def parse_tlvs(data):
    result, offset = [], 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ProtocolError('truncated element header')
        kind, length = struct.unpack_from('!HH', data, offset)
        offset += 4
        if length > len(data) - offset:
            raise ProtocolError('element length exceeds packet')
        result.append((kind, data[offset:offset + length]))
        offset += length
        if len(result) > 512:
            raise ProtocolError('too many elements')
    return result

def vendor(kind, value, container=None):
    return tlv(37, struct.pack('!IH', VENDOR, kind if container is None else container) + tlv(kind, value))

def private_elements(elements):
    result = []
    for kind, value in elements:
        if kind != 37:
            continue
        if len(value) < 6:
            raise ProtocolError('short vendor element')
        vendor_id, container = struct.unpack_from('!IH', value)
        if vendor_id == VENDOR:
            result.extend(parse_tlvs(value[6:]))
    return result

@dataclass
class Header:
    word: int
    fragment_id: int
    offset: int
    length: int

    @property
    def fragmented(self): return bool(self.word & 0x80)
    @property
    def last(self): return bool(self.word & 0x40)
    @property
    def radio(self): return (self.word >> 14) & 31
    @property
    def binding(self): return (self.word >> 9) & 31

def header(data):
    if len(data) < 8:
        raise ProtocolError('short CAPWAP header')
    word, frag, off = struct.unpack_from('!IHH', data)
    if word >> 24:
        raise ProtocolError('unsupported CAPWAP version/type (DTLS requires transport decoder)')
    size = ((word >> 19) & 31) * 4
    if size < 8 or size > len(data) or off & 7:
        raise ProtocolError('invalid CAPWAP header length/fragment offset')
    if not word & 0x80 and (off or word & 0x40):
        raise ProtocolError('fragment flags inconsistent')
    return Header(word, frag, (off >> 3) * 8, size)

@dataclass
class Message:
    kind: int
    sequence: int
    elements: list
    radio: int = 0
    binding: int = 1

    def values(self, kind): return [v for t, v in self.elements if t == kind]
    def private(self, kind): return [v for t, v in private_elements(self.elements) if t == kind]

def decode(data):
    h = header(data)
    if h.fragmented:
        raise ProtocolError('fragment needs reassembly')
    if h.word & 8:
        raise ProtocolError('data keepalive is not a control message')
    if len(data) < h.length + 8:
        raise ProtocolError('short control header')
    kind, sequence, length, flags = struct.unpack_from('!IBHB', data, h.length)
    # Firmware fixtures and cw_control_header_assemble: length includes its
    # own two bytes and the following flags byte, but excludes type and seq.
    if flags or length < 3 or h.length + 5 + length != len(data):
        raise ProtocolError('invalid control message length/flags')
    elements = parse_tlvs(data[h.length + 8:])
    private_elements(elements)  # Validate nested lengths before accepting.
    return Message(kind, sequence, elements, h.radio, h.binding)

def encode(kind, sequence, elements=b'', radio=0, binding=1):
    if not 0 <= sequence <= 255 or not 0 <= radio <= 31 or not 0 <= binding <= 31:
        raise ProtocolError('invalid control header value')
    if len(elements) > 65532:
        raise ProtocolError('message too large')
    word = (2 << 19) | (radio << 14) | (binding << 9) | 0x100
    return struct.pack('!IHHIBHB', word, 0, 0, kind, sequence, len(elements) + 3, 0) + elements

def fragment(packet, ident, mtu=1100):
    h = header(packet)
    if len(packet) <= mtu:
        return [packet]
    size = ((mtu - h.length) // 8) * 8
    if size < 8:
        raise ProtocolError('MTU too small')
    payload = packet[h.length:]
    result = []
    for offset in range(0, len(payload), size):
        part = payload[offset:offset + size]
        flags = 0x80 | (0x40 if offset + len(part) == len(payload) else 0)
        result.append(struct.pack('!IHH', h.word | flags, ident & 65535, offset) + packet[8:h.length] + part)
    return result

class Reassembler:
    def __init__(self, limit=64, timeout=5, max_size=65535):
        self.pending, self.limit, self.timeout, self.max_size = {}, limit, timeout, max_size

    def feed(self, peer, data, now=None):
        now = time.monotonic() if now is None else now
        self.pending = {k: v for k, v in self.pending.items() if now - v['time'] < self.timeout}
        h = header(data)
        if not h.fragmented:
            return data
        part = data[h.length:]
        if not part or (not h.last and len(part) % 8) or h.offset + len(part) > self.max_size:
            raise ProtocolError('invalid fragment extent')
        key = (peer, h.fragment_id)
        canonical = struct.pack('!IHH', h.word & ~0xc0, 0, 0) + data[8:h.length]
        if key not in self.pending:
            if len(self.pending) >= self.limit:
                raise ProtocolError('fragment queue full')
            self.pending[key] = {'time': now, 'parts': {}, 'end': None, 'header': canonical}
        state = self.pending[key]
        try:
            if state['header'] != canonical:
                raise ProtocolError('inconsistent fragment headers')
            for offset, previous in state['parts'].items():
                if offset == h.offset and part == previous:
                    break
                if max(offset, h.offset) < min(offset + len(previous), h.offset + len(part)):
                    raise ProtocolError('overlapping fragments')
            state['parts'][h.offset] = part
            if len(state['parts']) > 512:
                raise ProtocolError('too many fragments')
            if h.last:
                end = h.offset + len(part)
                if state['end'] is not None and state['end'] != end:
                    raise ProtocolError('conflicting final fragment')
                state['end'] = end
            if state['end'] is not None and any(o + len(p) > state['end'] for o, p in state['parts'].items()):
                raise ProtocolError('fragment beyond final extent')
            offset, chunks = 0, []
            for start, chunk in sorted(state['parts'].items()):
                if start != offset: return None
                chunks.append(chunk); offset += len(chunk)
            if offset != state['end']: return None
            del self.pending[key]
            return canonical + b''.join(chunks)
        except ProtocolError:
            self.pending.pop(key, None)
            raise

def identity(message):
    result = {'radio_ids': [], 'private_types': sorted({t for t, _ in private_elements(message.elements)})}
    for value in message.values(38):
        if len(value) < 4: raise ProtocolError('short board data')
        for kind, field in parse_tlvs(value[4:]):
            if kind == 4 and len(field) == 6:
                result['mac'] = ':'.join('%02x' % x for x in field)
            elif kind == 0:
                result['model_id'] = field.hex()
            elif kind == 1:
                result['serial'] = field.rstrip(b'\0').decode('utf-8', 'replace')[:128]
    for value in message.values(1048):
        if len(value) == 5 and value[0] not in result['radio_ids']:
            result['radio_ids'].append(value[0])
    versions = message.private(0)
    if versions:
        result['protocol_version'] = versions[0].hex()
    for value in message.values(50):
        if len(value)==16:
            words=struct.unpack('!4I',value)
            # _uac_wserv_add_packet_create checks capability 63, then 32.
            result['wireless_dialect']='extended' if words[1] & (1<<31) else 'modern99' if words[1]&1 else 'legacy9'
    # Firmware _apdb_pkt_manage: v1 header is 16 bytes, followed by
    # count-at-15 records with one-byte type and one-byte length.
    for database in message.private(81):
        if len(database)<16 or database[0]!=1: continue
        offset=16
        for _ in range(database[15]):
            if offset+2>len(database): raise ProtocolError('short APDB item')
            kind,length=database[offset:offset+2];offset+=2
            if offset+length>len(database): raise ProtocolError('short APDB value')
            value=database[offset:offset+length];offset+=length
            if kind==1:
                result['model_name']=value.rstrip(b'\0').decode('utf8','replace')[:128]
            elif kind==7 and len(value)>=4:
                radio=len(result.setdefault('radios',[]))+1
                detail={'id':radio,'band':{0:'2.4 GHz',1:'5 GHz'}.get(value[0],'未知频段')}
                pos=4
                for _ in range(value[1]):
                    if pos+2>len(value): raise ProtocolError('short APDB radio item')
                    typ,size=value[pos:pos+2];pos+=2
                    if pos+size>len(value): raise ProtocolError('short APDB radio value')
                    if typ==1 and size==2: detail['max_ssids']=int.from_bytes(value[pos:pos+size],'big')
                    short_fields={2:'max_stations',3:'max_power',4:'min_power',5:'default_power',
                                  11:'real_max_power',12:'real_min_power',13:'real_default_power'}
                    byte_fields={6:'support_ac',8:'default_bw',9:'support_160',10:'support_ax',
                                 14:'support_80_80',16:'tx_streams',17:'rx_streams',18:'support_wpa3',
                                 21:'support_be',22:'support_240',24:'function_type'}
                    if typ in short_fields and size==2: detail[short_fields[typ]]=int.from_bytes(value[pos:pos+size],'big')
                    if typ in byte_fields and size==1: detail[byte_fields[typ]]=value[pos]
                    if typ==7: detail['mutex_channels']=value[pos:pos+size].rstrip(b'\0').decode('ascii','replace')
                    pos+=size
                if pos!=len(value): raise ProtocolError('inconsistent APDB radio count')
                result['radios'].append(detail)
        if offset!=len(database): raise ProtocolError('inconsistent APDB count')
        result['hardware_version']=str(database[2])+'.'+str(database[3])
    return result

def wlan_report(message):
    """Read AP inventory without retaining security parameters or keys."""
    reports = message.private(30)
    if not reports: return None
    rows = []
    for data in reports:
        if len(data)<8: raise ProtocolError('short WLAN inventory')
        operation,count=struct.unpack_from('!II',data)
        if operation!=1 or count>512 or len(data)!=8+33*count:
            raise ProtocolError('invalid WLAN inventory')
        for i in range(count):
            start=8+33*i
            rows.append({'radio':data[start], 'ssid':data[start+1:start+33].split(b'\0',1)[0].decode('utf8','replace')})
    return rows

def wlan_elements(ssid, key, radio=1, wlan=1, vlan=0, dialect=9, hidden=False, isolate=False,
                  encryption=1,auth=2,cipher=2,key_interval=86400):
    """Legacy (9) and newer (99) open/PSK payloads share this verified layout.

    SSID uses standard element 1024; private service parameters carry PSK.
    This does not imply model compatibility or implement MLO/WPA3.
    """
    name = ssid.encode('utf-8')
    if not 1 <= len(name) <= 32 or b'\0' in name:
        raise ProtocolError('SSID must contain 1..32 UTF-8 bytes without NUL')
    if not 1 <= radio <= 31 or not 1 <= wlan <= 16 or not 0 <= vlan <= 4094 or dialect not in (9,99):
        raise ProtocolError('invalid radio/WLAN/VLAN/service dialect')
    values=[]
    for value in (encryption,auth,cipher,key_interval):
        if isinstance(value,bool) or not re.fullmatch(r'\d+',str(value)): raise ProtocolError('invalid wireless security parameter')
        values.append(int(value))
    encryption,auth,cipher,key_interval=values
    if encryption not in (0,1) or auth not in (1,2,3) or cipher not in (0,1,2):
        raise ProtocolError('unsupported wireless security mode')
    if key_interval!=0 and not 30<=key_interval<=604800: raise ProtocolError('密钥更新周期为 0 或 30–604800 秒')
    if encryption:
        try: password=key.encode('ascii')
        except (AttributeError,UnicodeEncodeError) as error: raise ProtocolError('密码需为可打印 ASCII 字符') from error
        if not (8 <= len(password) <= 63 and all(32 <= b <= 126 for b in password)
                or len(password)==64 and re.fullmatch(b'[0-9a-fA-F]{64}',password)):
            raise ProtocolError('密码需为 8–63 个可打印 ASCII 字符或 64 位十六进制密钥')
    # Firmware _uac_wserv_add_packet_create and cw_80211_add_wlan_assemble.
    add = struct.pack('!BBHBBH', radio, wlan, 0x8000, 0, 0, 0)
    # The vendor feeds its ssidbrd flag directly here (1 = broadcast).
    add += bytes(6) + bytes((0, 0, 0, 1, int(not hidden))) + name
    # radio, wlan, VLAN, max users, network type, isolation, security option.
    service = struct.pack('!BBHHBBB', radio, wlan, vlan, 64, 3, int(isolate), encryption)
    # Security 0 ends after the base fields; security 1 includes PSK parameters.
    # Confirmed in both assembler jump tables; 0x8000 above is constant, not privacy.
    if encryption: service += struct.pack('!BBIH',auth,cipher,key_interval,len(password))+password
    return tlv(1024, add) + vendor(dialect, service)

def delete_wlan_elements(radio,wlan):
    if not 1<=radio<=31 or not 1<=wlan<=16: raise ProtocolError('invalid radio/WLAN')
    return tlv(1027,bytes((radio,wlan)))
