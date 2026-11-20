import sys
import struct
import tempfile
import time
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from tplink_ac.station_policy import association_denials,association_results,admission_elements,delete_station
from tplink_ac.protocol import encode,decode,tlv,vendor,ProtocolError
from tplink_ac.web import Application
from tplink_ac.controller import Controller

MAC='02:00:00:00:00:01'
PREFIX=b'\x01\x07'+bytes.fromhex(MAC.replace(':',''))

class StationPolicyTests(unittest.TestCase):
    def test_status_does_not_share_live_station_maps(self):
        c=Controller({},lambda *a:None,clock=lambda:10)
        peer=('192.0.2.155',1000)
        c.peers[peer]={'last_seen':10,'stations':{MAC:{'radio':1,'seen':9}}}
        saved=c.status()
        for mac,station in saved['aps'][0]['stations'].items():
            c.peers[peer]['stations'].pop(mac)
            station['radio']=2
        self.assertEqual(saved['aps'][0]['stations'][MAC]['radio'],2)
        self.assertEqual(c.peers[peer]['stations'],{})

    def test_disconnect_preflights_batch_and_uses_latest_association(self):
        with tempfile.TemporaryDirectory() as directory:
            app=Application(ROOT/'web',directory);calls=[];now=time.monotonic()
            app.service.snapshot=lambda:{'aps':[
                {'ip':'192.0.2.152','state':'run','secure':True,'last_seen_seconds':0,
                 'stations':{MAC:{'seen':now-20}}},
                {'ip':'192.0.2.155','state':'run','secure':True,'last_seen_seconds':0,
                 'stations':{MAC:{'seen':now-1}}}]}
            app.confirm_action=lambda *a:calls.append(a)
            with self.assertRaises(ValueError): app.station_policy.disconnect([MAC,'02:00:00:00:00:03'])
            self.assertEqual(calls,[])
            result=app.ds({'method':'do','host_management':{'disconnect':{'mac_list':[MAC]}}})
            self.assertEqual(result['completed'],[MAC])
            self.assertEqual(calls,[('192.0.2.155','disconnect',{'mac':MAC})])
            self.assertEqual(app.station_policy.rules,{})

    def test_legacy_and_modern_preserve_opaque_backfill(self):
        opaque=b'\xff\x00\x31opaque'
        for extra in (b'',struct.pack('!i',-65)):
            request=decode(encode(9,1,vendor(2,PREFIX+extra+struct.pack('!I',len(opaque))+opaque)))
            self.assertEqual(association_denials(request,set()),b'')
            result=decode(encode(10,1,association_denials(request,{MAC})))
            self.assertEqual(result.private(4),[PREFIX+struct.pack('!II',40,len(opaque))+opaque])
            allowed=decode(encode(10,1,association_results(request,set())))
            self.assertEqual(allowed.private(4),[PREFIX+struct.pack('!II',0,len(opaque))+opaque])
        parts=tlv(0,opaque)+tlv(1,b'mlo')
        request=decode(encode(9,1,vendor(138,PREFIX+struct.pack('!iBI',-65,1,len(parts))+parts)))
        result=decode(encode(10,1,association_denials(request,{MAC}))).private(139)[0]
        wanted=tlv(1,opaque)+tlv(2,b'')
        self.assertEqual(result,PREFIX+struct.pack('!IBI',40,1,len(wanted))+wanted)
        allowed=decode(encode(10,1,association_results(request,set()))).private(139)[0]
        self.assertEqual(allowed,PREFIX+struct.pack('!IBI',0,1,len(wanted))+wanted)
        with self.assertRaises(ProtocolError):
            association_denials(decode(encode(9,1,vendor(138,PREFIX+b'bad'))),{MAC})

    def test_disconnect_uses_current_station_and_ack(self):
        sent=[];c=Controller({'enabled':True,'allowed_ips':['127.0.0.1'],'dtls':True},lambda *a:sent.append(a),clock=lambda:10)
        peer=('127.0.0.1',1000)
        c.peers[peer]={'ip':peer[0],'state':'run','last_seen':10,'secure':True,'pending':None,
            'radio_ids':[1],'private_types':[],'cache':{},'stations':{MAC:{'radio':1,'seen':9}},'mac':'02:00:00:00:00:02'}
        action=c.operation(peer[0],'disconnect',{'mac':MAC})
        request=decode(sent[-1][1]);self.assertEqual(request.kind,25)
        self.assertEqual(request.values(18),[b'\x01\x06'+PREFIX[2:]])
        c.receive(peer,encode(26,action['sequence'],tlv(33,bytes(4))),True)
        self.assertEqual(c.results[action['id']]['status'],'acknowledged')
        with self.assertRaises(ProtocolError): delete_station(c.peers[peer],{'mac':MAC},200)
        c.blocked_stations=frozenset({MAC})
        request=encode(9,100,vendor(2,PREFIX+bytes(4)))
        c.receive(peer,request,True)
        self.assertEqual(decode(sent[-1][1]).values(33),[struct.pack('!I',21)])
        self.assertTrue(decode(sent[-1][1]).private(4))

    def test_persistence_filter_and_atomic_import(self):
        with tempfile.TemporaryDirectory() as directory:
            app=Application(ROOT/'web',directory)
            app.station_policy.change([MAC],{'blocked':'1','hostname':'Test'})
            restored=Application(ROOT/'web',directory)
            self.assertEqual(restored.service.blocked_stations,{MAC})
            result=restored.ds({'method':'get','host_management':{'table':'host_info','filter':[{'blocked':'1'}]}})
            self.assertEqual(result['host_management']['host_info_count'],1)
            text=app.station_policy.csv().decode('utf8')
            self.assertEqual(app.station_policy.import_plan(text),[{'mac':MAC,'hostname':'Test'}])
            with self.assertRaises(ValueError): app.station_policy.import_csv(text+'bad,Invalid\n')
            self.assertEqual(app.station_policy.rules,{MAC:'Test'})
            restored.station_policy.change([MAC],{'blocked':'0'})
            self.assertEqual(restored.service.blocked_stations,set())

    def test_admission_targets_are_explicit_and_persistent(self):
        self.assertEqual(decode(encode(7,0,admission_elements({'enable':True}))).private(38),[bytes.fromhex('0000006f0000002e')])
        with self.assertRaises(ValueError): admission_elements({'enable':1})
        with tempfile.TemporaryDirectory() as directory:
            app=Application(ROOT/'web',directory);calls=[]
            ap={'mac':MAC,'entry_name':'Test','ip':'192.0.2.155','session_epoch':'first','management_state':'managed'}
            other=ap|{'mac':'02:00:00:00:00:02','ip':'192.0.2.152','management_state':'offline'}
            app.ap_rows=lambda:[ap,other];app.confirm_action=lambda *a:calls.append(a)
            with self.assertRaises(ValueError):app.station_policy.enable_admission([MAC,other['mac']])
            self.assertFalse(calls)
            app.station_policy.enable_admission([MAC]);self.assertEqual(len(calls),1)
            restored=Application(ROOT/'web',directory)
            self.assertEqual(set(restored.station_policy.admission_aps),{MAC})
            ap['session_epoch']='second';app.station_policy.reconcile()
            self.assertEqual(len(calls),2);self.assertEqual(calls[-1][0],'192.0.2.155')

if __name__=='__main__':unittest.main()
