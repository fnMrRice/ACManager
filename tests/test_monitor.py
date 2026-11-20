import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from tplink_ac.protocol import decode,encode,vendor,tlv,ProtocolError
from tplink_ac.telemetry import station_reports,receive,statistics_control
from tplink_ac.monitor import Monitor,local_hosts
from tplink_ac.web import Application,Unsupported


def report():
    # Firmware packed layout: 6-byte MAC, six u8, u16, u32, u16,
    # two u8, and four u32. Numeric values deliberately differ.
    row=bytes.fromhex('020000000011')+struct.pack('!BBBBbBHIHBBIIII',2,7,2,2,-57,80,866,0x1234,0x5678,3,4,123,456,789,987)
    return decode(encode(9,1,vendor(82,struct.pack('!I',1)+row)))


class TelemetryTests(unittest.TestCase):
    def test_firmware_layout(self):
        received,rows,departures=station_reports(report())
        self.assertTrue(received);self.assertEqual(departures,[])
        self.assertEqual(rows[0],{'mac':'02:00:00:00:00:11','radio':2,'wlan':7,'rssi':-57,
                                 'nego_rate':866,'upstream_rate':123,'downstream_rate':456,'source':'statistics'})
        self.assertEqual(decode(encode(7,1,statistics_control())).private(85),[bytes.fromhex('010001001400140014')])

    def test_partial_reports_expiry_departure_and_atomic_validation(self):
        ap={};receive(ap,report(),10)
        receive(ap,decode(encode(9,2,vendor(82,bytes(4)))),20)
        self.assertEqual(len(ap['stations']),1) # Empty/partial packet isn't a full snapshot.
        before=copy.deepcopy(ap)
        bad=decode(encode(9,3,vendor(82,bytes.fromhex('ffffffff'))))
        with self.assertRaises(ProtocolError): receive(ap,bad,30)
        self.assertEqual(ap,before)
        receive(ap,decode(encode(9,4,vendor(3,bytes.fromhex('0207020000000011')))),40)
        self.assertEqual(ap['stations'],{})
        receive(ap,report(),50)
        receive(ap,decode(encode(9,5,vendor(82,bytes(4)))),151)
        self.assertEqual(ap['stations'],{})

    def test_ap_radio_statistics_and_bounds(self):
        header=bytes((1,1,2,10,20))+bytes(6)+bytes((35,))+bytes(2)+bytes(28)
        radio=struct.pack('!BBHHHbBBBIIIIBBBB',2,149,3,20,1,-95,12,2,1,100,200,3,4,5,6,7,8)
        wlan=bytes((2,7))+bytes.fromhex('020000000021')+bytes(20)
        packet=decode(encode(9,5,vendor(84,header+radio+wlan)))
        ap={};receive(ap,packet,100)
        self.assertEqual(ap['radio_statistics']['2']['channel'],149)
        self.assertEqual(ap['radio_statistics']['2']['tx_power'],20)
        self.assertEqual(ap['radio_statistics']['2']['noise'],-95)
        self.assertEqual(ap['reported_bssids']['2:7'],'02:00:00:00:00:21')
        before=copy.deepcopy(ap)
        with self.assertRaises(ProtocolError):receive(ap,decode(encode(9,6,vendor(84,header+radio+wlan[:-1]))),110)
        self.assertEqual(ap,before)

    def test_standard_inventory_and_rssi(self):
        fields=tlv(52,struct.pack('!BII',1,2,1)+struct.pack('!II',10,20)+bytes.fromhex('020000000011'))
        fields+=tlv(51,struct.pack('!BI',1,1)+bytes.fromhex('020000000011c4'))
        ap={};receive(ap,decode(encode(9,3,fields)),5)
        self.assertEqual(ap['stations']['02:00:00:00:00:11']['rssi'],-60)
        self.assertEqual(ap['stations']['02:00:00:00:00:11']['wlan'],2)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.app=Application(ROOT/'web',self.temp.name)
        self.app.config.update(enabled=True,auto_adopt=True,adopt_subnets=['192.0.2.0/24'])
        self.ap={'ip':'192.0.2.155','mac':'02:00:00:00:00:01','state':'run','secure':True,
                 'last_seen_seconds':0,'last_seen':100,'radio_ids':[1,2],'radios':[{'id':2,'band':'5 GHz'}]}
        receive(self.ap,report(),100)
        self.status={'aps':[self.ap],'running':True,'events':[]}
        self.app.service.snapshot=lambda:copy.deepcopy(self.status)
        self.now=100
        self.app.monitor=Monitor(self.app,lambda:self.now,lambda:{'02:00:00:00:00:11':{'hostname':'Phone','ip':'192.0.2.200'},'02:ff:00:00:00:01':{'hostname':'Wired'}})
        self.app.profiles['1']={'ssid':'AC-Test-155'}
        self.app.bindings[('1','258')]={'mac':self.ap['mac'],'radio':2,'wlan':7,'active':True,'vlan':0}

    def test_real_association_only_and_offline(self):
        rows=self.app.monitor.rows()
        self.assertEqual(len(rows),1)
        row=rows[0];self.assertEqual((row['ip'],row['ssid'],row['hostname']),('192.0.2.200','AC-Test-155','Phone'))
        self.assertEqual(row['online_status'],'1')
        self.now=201
        row=self.app.monitor.rows()[0]
        self.assertEqual(row['online_status'],'0');self.assertIsNone(row['upstream_rate'])
        self.now=3800;self.assertEqual(self.app.monitor.rows(),[])

    def test_roaming_chooses_newest_association(self):
        other=copy.deepcopy(self.ap);other.update(mac='02:00:00:00:00:02',ip='192.0.2.153',last_seen=105)
        other['stations']['02:00:00:00:00:11']['seen']=105
        self.status['aps'].append(other);self.now=110
        rows=self.app.monitor.rows();self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['ap_ip'],'192.0.2.153')
        self.assertEqual(rows[0]['ssid'],'未读取')

    def test_name_save_export_and_no_fake_blocking(self):
        self.app.ds({'method':'set','hostManagement':{'table':'host_info','filter':[{'mac':'02:00:00:00:00:11'}],'para':{'hostname':'=测试名称'}}})
        self.assertEqual(json.loads((Path(self.temp.name)/'terminals.json').read_text(encoding='utf8'))['02:00:00:00:00:11'],'=测试名称')
        self.assertIn("'=测试名称",self.app.monitor.csv().decode('utf8'))
        with self.assertRaises(ValueError):
            self.app.ds({'method':'set','host_management':{'table':'host_info','para':{'blocked':'1'}}})
        self.assertEqual(self.app.station_policy.rules,{})

    def test_native_table_count_and_filters(self):
        result=self.app.ds({'method':'get','hostManagement':{'table':'host_info','filter':[{'hostname':'Pho','groupId':['-1'],'dataType':['sta_info']}],'para':{'start':0,'end':9}}})
        self.assertEqual(result['host_management']['count']['host_info'],1)
        self.assertEqual(len(result['host_management']['host_info']),1)
        result=self.app.ds({'method':'get','host_management':{'table':'host_info','filter':[{'blocked':'1'}]}})
        self.assertEqual(result['host_management']['count']['host_info'],0)
        rows,_=self.app.table([{'mac':'a'},{'mac':'b'}],'x',{'filter':[{'mac':'a'},{'mac':'b'}]})
        self.assertEqual(len(rows),2)

    def test_topology_edges_and_filters(self):
        data=self.app.monitor.topology()
        nodes={n['mac']:n for n in data['devList']}
        self.assertTrue(all(e['srcMac'] in nodes and e['destMac'] in nodes for e in data['edgeList']))
        self.assertEqual(data['client_count'],1);self.assertEqual(data['ap_count'],1)
        self.assertEqual(nodes[self.ap['mac']]['onlineStatus'],1)
        self.assertEqual(self.app.monitor.topology('offline')['ap_count'],0)
        self.status['aps'][0]['state']='offline';self.status['aps'][0]['last_seen_seconds']=120
        data=self.app.monitor.topology('offline')
        self.assertEqual((data['ap_count'],data['client_count']),(1,0))

    def test_dhcp_expiry_and_arp(self):
        base=Path(self.temp.name);leases=base/'leases';arp=base/'arp'
        arp.write_text('IP HW FLAGS MAC MASK DEVICE\n192.0.2.2 0x1 0x2 02:00:00:00:00:02 * br-lan\n')
        leases.write_text('10 02:00:00:00:00:01 192.0.2.1 expired *\n200 02:00:00:00:00:02 192.0.2.2 phone *\n')
        self.assertEqual(local_hosts(leases,arp,100),{'02:00:00:00:00:02':{'ip':'192.0.2.2','hostname':'phone'}})


if __name__=='__main__': unittest.main()
