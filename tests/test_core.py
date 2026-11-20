import sys
import unittest
import struct
import tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'src'),str(ROOT/'.tools/python')]
from tplink_ac.protocol import *
from tplink_ac.controller import Controller
from tplink_ac.service import DEFAULTS,validate_config
from tplink_ac.web import Application,Unsupported

BOARD = tlv(38,struct.pack('!I',VENDOR)+tlv(4,bytes.fromhex('020000000001'))+tlv(0,b'LAB1'))
RADIO = tlv(1048,b'\x01\0\0\0\x01')
SID = tlv(35,b'S'*16)

# Handwritten wire bytes, independent of the codec helpers and captured traffic.
# The board uses only test identities; APDB contains TestAP and two test radios.
TEST_DISCOVERY = (
    bytes.fromhex('0010030000000000 000000012a008600')
    + bytes.fromhex('00260021 12345678 00000004 00000001 00010007')
    + b'LAB0001'
    + bytes.fromhex('00040006 020000000002')
    + bytes.fromhex('04180005 0100000001 04180005 0200000001')
    + bytes.fromhex('0025000e 12345678 0000 00000004 00000001')
    + bytes.fromhex('00250036 12345678 0051 0051002c')
    + bytes.fromhex('01000100 00000000 00000000 00000003 0106')
    + b'TestAP'
    + bytes.fromhex('0708 00010000 01020008 0708 01010000 01020008')
)

class CodecTests(unittest.TestCase):
    def test_synthetic_apdb_discovery(self):
        info=identity(decode(TEST_DISCOVERY))
        self.assertEqual(info['mac'],'02:00:00:00:00:02')
        self.assertEqual(info['serial'],'LAB0001')
        self.assertEqual(info['model_id'],'00000001')
        self.assertEqual(info['hardware_version'],'1.0')
        self.assertEqual(info['model_name'],'TestAP')
        self.assertEqual(info['radio_ids'],[1,2])
        self.assertEqual(info['protocol_version'],'00000001')
        self.assertEqual(info['private_types'],[0,81])
        self.assertEqual(info['radios'],[
            {'id':1,'band':'2.4 GHz','max_ssids':8},
            {'id':2,'band':'5 GHz','max_ssids':8},
        ])

    def test_synthetic_control_messages(self):
        headers = [('000000012a008600',1),('000000022a008600',2),
                   ('000000032a008600',3),('000000042a008600',4),
                   ('000000062a008600',6),('000000072a008600',7),
                   ('0000000b2a008600',11),('0033dd012a008600',WLAN_REQUEST)]
        for control,kind in headers:
            with self.subTest(kind=kind):
                packet=TEST_DISCOVERY[:8]+bytes.fromhex(control)+TEST_DISCOVERY[16:]
                m=decode(packet)
                self.assertEqual(m.kind,kind)
                self.assertEqual((m.sequence,m.radio,m.binding),(42,0,1))
                self.assertEqual(encode(m.kind,m.sequence,b''.join(tlv(t,v) for t,v in m.elements),m.radio,m.binding),packet)

    def test_bad_lengths(self):
        good=bytes.fromhex('0010030000000000 0000000d01000300')
        for bad in (b'',good[:-1],good+b'\0',
                    bytes.fromhex('0010030000000000 0000000100000a00 00250003 313233'),
                    bytes.fromhex('0010030000000000 0000000500000900 00210004 0000'),
                    bytes.fromhex('0010030000000000 0000000100001100 0025000a 12345678 0001 00010001')):
            with self.assertRaises(ProtocolError): decode(bad)

    def test_fragment_order_duplicates_and_overlap(self):
        data=encode(1,2,tlv(4,b'x'*4000))
        parts=fragment(data,42,500)
        r=Reassembler()
        self.assertIsNone(r.feed('p',parts[-1],0))
        self.assertIsNone(r.feed('p',parts[-1],0))
        result=None
        for part in parts[:-1]: result=r.feed('p',part,1)
        self.assertEqual(result,data)
        r.feed('p',parts[0],2)
        bad=bytearray(parts[1]);bad[6:8]=struct.pack('!H',8)
        with self.assertRaises(ProtocolError): r.feed('p',bytes(bad),2)
        self.assertFalse(r.pending)

    def test_fragment_limits(self):
        data=fragment(encode(1,0,tlv(4,b'x'*100)),1,40)
        r=Reassembler(limit=1)
        r.feed('a',data[0],0)
        with self.assertRaises(ProtocolError): r.feed('b',data[0],0)
        r.feed('b',data[0],6)
        self.assertEqual(len(r.pending),1)

    def test_wlan_bytes(self):
        fields=parse_tlvs(wlan_elements('Lab','password',vlan=20,radio=2,dialect=99))
        self.assertEqual(fields[0][0],1024)
        self.assertEqual(fields[0][1][:8],bytes.fromhex('0201800000000000'))
        self.assertEqual(fields[0][1][-4:],b'\x01Lab')
        self.assertEqual(private_elements(fields),[(99,bytes.fromhex('0201001400400300010202000151800008')+b'password')])
        for kwargs in ({'vlan':4095},{'radio':0},{'ssid':'x'*33},{'key':'short'}):
            with self.assertRaises(ValueError): wlan_elements(**({'ssid':'Lab','key':'password'}|kwargs))

class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.sent=[]; self.now=0
        self.c=Controller(DEFAULTS|{'enabled':True,'allowed_ips':['127.0.0.1'],'dtls':True},lambda *x:self.sent.append(x),lambda:self.now)
        self.peer=('127.0.0.1',10000)

    def ready(self):
        for kind,fields in ((1,BOARD+RADIO+vendor(9,b'')),(3,BOARD+SID),(5,b''),(11,b'')):
            self.c.receive(self.peer,encode(kind,kind,fields),kind!=1)
        self.assertEqual(self.c.peers[self.peer]['state'],'run')

    def test_lifecycle_and_ack(self):
        self.ready()
        pending=self.c.operation('127.0.0.1','apply',{'ssid':'Lab','key':'password'})
        m=decode(self.sent[-1][1]);self.assertEqual(m.kind,WLAN_REQUEST)
        self.assertEqual(self.c.status()['aps'][0]['last_operation']['status'],'pending')
        self.c.receive(self.peer,encode(WLAN_RESPONSE,pending['sequence'],tlv(33,bytes(4))),True)
        self.assertEqual(self.c.status()['aps'][0]['last_operation']['status'],'acknowledged')
        self.assertNotIn('password',str(self.c.status()))

    def test_auth_and_state(self):
        self.c.receive(self.peer,encode(3,1,BOARD+SID),False)
        self.assertEqual(self.sent,[])
        with self.assertRaises(ProtocolError): self.c.operation('127.0.0.1','led_on')
        self.c.receive(('127.0.0.2',4),encode(1,1,BOARD),False)
        self.assertEqual(self.sent,[])

    def test_cache_and_timeout(self):
        self.ready()
        packet=encode(13,50)
        self.c.receive(self.peer,packet,True)
        first=self.sent[-1]
        self.c.receive(self.peer,packet,True)
        self.assertEqual(first,self.sent[-1])
        self.c.operation('127.0.0.1','led_on')
        for t in (3,6,9): self.now=t; self.c.tick()
        self.assertEqual(self.c.status()['aps'][0]['last_operation']['status'],'timeout')

    def test_missing_and_rejected_ack(self):
        self.ready()
        p=self.c.operation('127.0.0.1','led_off')
        self.c.receive(self.peer,encode(8,p['sequence']),True)
        self.assertEqual(self.c.status()['aps'][0]['last_operation']['status'],'unconfirmed')
        p=self.c.operation('127.0.0.1','led_on')
        self.c.receive(self.peer,encode(8,p['sequence'],tlv(33,struct.pack('!I',3))),True)
        self.assertEqual(self.c.status()['aps'][0]['last_operation']['status'],'rejected')

    def test_discovery_does_not_downgrade_dtls(self):
        self.ready()
        self.c.receive(self.peer,encode(1,80,BOARD),False)
        self.assertTrue(self.c.peers[self.peer]['secure'])
        self.c.operation('127.0.0.1','led_on')
        self.assertTrue(self.sent[-1][2])

    def test_operation_history_survives_later_commands(self):
        self.ready()
        p=self.c.operation('127.0.0.1','led_on')
        self.c.receive(self.peer,encode(8,p['sequence'],tlv(33,bytes(4))),True)
        self.c.operation('127.0.0.1','led_off')
        self.assertEqual(self.c.status()['operations'][p['id']]['status'],'acknowledged')

    def test_send_failure_not_left_pending(self):
        self.ready()
        def failed(*args): raise OSError('transport gone')
        self.c.send=failed
        with self.assertRaises(OSError): self.c.operation('127.0.0.1','led_on')
        self.assertIsNone(self.c.peers[self.peer]['pending'])
        self.assertEqual(self.c.peers[self.peer]['last_operation']['status'],'send_failed')

class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.a=Application(ROOT/'web',self.temp.name)

    def test_table_paging(self):
        rows=[{'entry_id':str(n)} for n in range(20)]
        result,count=self.a.table(rows,'ap_list',{'index':{'start':10,'end':19}})
        self.assertEqual((len(result),count),(10,20))
        self.assertIn('ap_list_10',result[0])

    def test_unknown_write_fails(self):
        with self.assertRaises(Unsupported): self.a.ds({'method':'do','system':{'reboot':{}}})

    def test_repeated_discovery_has_one_ui_row(self):
        self.a.service.snapshot = lambda: {'aps':[
            {'ip':'192.0.2.152','mac':'02:00:00:00:00:01','state':'offline','last_seen_seconds':150},
            {'ip':'192.0.2.152','mac':'02:00:00:00:00:01','state':'observed','last_seen_seconds':2}]}
        rows = self.a.ap_rows()
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['status'],'observed')
        self.assertEqual(rows[0]['link_status'],'2')
        # The firmware hides every entry in authorize_ap_list from its status
        # table. A transport allowlist must not populate that Mesh queue.
        self.assertEqual(self.a.get_value('apmng_set','authorize_ap_list'),[])
        self.assertEqual(rows[0]['management_state'],'discovered')
        self.assertEqual(self.a.get_value('apmng_status','ap_link_status'),{'online_num':'0','offline_num':'0','discovered_num':'1'})

    def test_profiles_and_preferences(self):
        p={'ssid':'Lab','key':'password','encryption':'1','auth':'2','cipher':'2'}
        r=self.a.ds({'method':'add','apmng_wserv':{'table':'wlan_serv','para':p}})
        self.assertTrue(r['local_only'])
        restored=Application(ROOT/'web',self.temp.name)
        self.assertEqual(restored.profiles['1']['ssid'],'Lab')
        self.assertEqual(restored.profiles['1']['key'],'password')
        self.a.ds({'method':'set','global_config':{'page_size':{'ap_list':'20'}}})
        self.assertEqual(self.a.get_value('global_config','page_size'),{'ap_list':'20'})
        self.a.ds({'method':'delete','apmng_wserv':{'table':'wlan_serv','filter':[{'serv_id':'1'}]}})
        self.assertFalse(self.a.profiles)

    def test_config_validation(self):
        for bad in ({'enabled':'yes'},{'ac_ip':'0.0.0.0'},{'control_port':5247},{'enabled':True},{'name':None}):
            with self.assertRaises(ValueError): validate_config(bad)

if __name__=='__main__': unittest.main()
