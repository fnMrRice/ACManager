"""Decode bounded station statistics, identity, and RSSI reports.

Station statistics use packed 38-byte rows. Reports never carry keys.
"""
import struct
from .protocol import ProtocolError, vendor

STA_TTL = 100


def statistics_control():
    # _stats_ctl_packet_create / cw_priv_statistics_control_assemble:
    # station, RSSI, AP switches; three unsigned 16-bit intervals in seconds.
    return vendor(85, struct.pack('!BBBHHH', 1, 0, 1, 20, 20, 20))


def mac_text(data):
    if len(data) != 6 or data == bytes(6) or data[0] & 1:
        raise ProtocolError('invalid station MAC')
    return ':'.join('%02x' % b for b in data)


def records(data, offset, count, size):
    if count > 1024 or len(data) != offset + count * size:
        raise ProtocolError('invalid station report length/count')
    return [data[i:i+size] for i in range(offset, len(data), size)]


def station_reports(message):
    updates, departures = [], []
    received = False
    for data in message.private(82):
        if len(data) < 4: raise ProtocolError('short station statistics')
        received = True
        for row in records(data, 4, int.from_bytes(data[:4], 'big'), 38):
            mac = mac_text(row[:6])
            radio, wlan = row[6:8]
            if not 1 <= radio <= 31 or not 1 <= wlan <= 16:
                raise ProtocolError('invalid station radio/WLAN')
            updates.append({'mac':mac, 'radio':radio, 'wlan':wlan,
                'rssi':struct.unpack_from('!b', row, 10)[0],
                'nego_rate':int.from_bytes(row[12:14], 'big'),
                'upstream_rate':int.from_bytes(row[22:26], 'big'),
                'downstream_rate':int.from_bytes(row[26:30], 'big'),
                'source':'statistics'})
    for data in message.values(52):
        if len(data) < 9: raise ProtocolError('short station inventory')
        received = True
        radio, wlan, count = struct.unpack_from('!BII', data)
        if not 1 <= radio <= 31 or not 1 <= wlan <= 16:
            raise ProtocolError('invalid station inventory radio/WLAN')
        for row in records(data, 9, count, 14):
            updates.append({'mac':mac_text(row[8:14]), 'radio':radio,
                            'wlan':wlan, 'source':'inventory'})
    for data in message.values(51):
        if len(data) < 5: raise ProtocolError('short station RSSI')
        radio, count = struct.unpack_from('!BI', data)
        if not 1 <= radio <= 31: raise ProtocolError('invalid station RSSI radio')
        for row in records(data, 5, count, 7):
            updates.append({'mac':mac_text(row[:6]), 'radio':radio,
                            'rssi':struct.unpack('!b',row[6:])[0]})
    for data in message.private(3):
        if len(data) != 8: raise ProtocolError('invalid station departure')
        departures.append((mac_text(data[2:]), data[0], data[1]))
    return received, updates, departures


def receive(ap, message, now):
    # Validate the complete report before modifying any station state.
    received, updates, departures = station_reports(message)
    hardware = ap_reports(message)
    if hardware is not None:
        ap.update(hardware)
        ap['radio_report_time'] = now
    stations = ap.setdefault('stations', {})
    if received: ap['station_report_time'] = now
    for update in updates:
        key = update['mac']
        old = stations.get(key, {})
        if 'wlan' not in update and not old: continue
        stations[key] = old | update | {'seen':now}
    for mac, radio, wlan in departures:
        old = stations.get(mac)
        if old and (old.get('radio'), old.get('wlan')) == (radio, wlan):
            del stations[mac]
    # A report may be split across packets; expiry is per station, never
    # replace the complete AP table with one partial/empty packet.
    ap['stations'] = {k:v for k,v in stations.items() if now-v['seen'] < STA_TTL}
    if len(ap['stations']) > 2048:
        ap['stations'] = dict(sorted(ap['stations'].items(), key=lambda kv:kv[1]['seen'])[-2048:])


def ap_reports(message):
    """Firmware cw_priv_ap_statistics_parse: 42-byte header, 32/28-byte rows."""
    reports = message.private(84)
    if not reports: return None
    radios,bssids={},{}
    result={}
    for data in reports:
        if len(data)<42: raise ProtocolError('short AP statistics')
        nr,nw,ncpu=data[:3]
        if nr>8 or nw>64 or not 1<=ncpu<=8 or len(data)!=42+nr*32+nw*28:
            raise ProtocolError('invalid AP statistics extent')
        result.update(cpu_usage=list(data[3:3+ncpu]),memory_usage=data[11])
        for i in range(nr):
            row=data[42+i*32:74+i*32]
            radio=row[0]
            if not 1<=radio<=31 or str(radio) in radios: raise ProtocolError('invalid AP statistics radio')
            radios[str(radio)]={'id':radio,'channel':row[1],
                'bandwidth':int.from_bytes(row[2:4],'big'),'tx_power':int.from_bytes(row[4:6],'big'),
                'noise':struct.unpack_from('!b',row,8)[0],'channel_load':row[9],
                'retry_rate':row[10],'loss_rate':row[11],
                'upstream_rate':int.from_bytes(row[12:16],'big'),'downstream_rate':int.from_bytes(row[16:20],'big')}
        for i in range(nw):
            offset=42+nr*32+i*28
            radio,wlan=data[offset:offset+2]
            if not 1<=radio<=31 or not 1<=wlan<=16: raise ProtocolError('invalid AP statistics WLAN')
            bssids[str(radio)+':'+str(wlan)]=mac_text(data[offset+2:offset+8])
    return result|{'radio_statistics':radios,'reported_bssids':bssids}
