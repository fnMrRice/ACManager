import sys
import time
import tempfile
import unittest
from pathlib import Path
from copy import deepcopy
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from tplink_ac.balance import Decisions,DEFAULTS,elements
from tplink_ac.protocol import encode,decode,vendor,tlv
from tplink_ac.web import Application
from tplink_ac.controller import Controller

A='02:00:00:00:00:01';B='02:00:00:00:00:02';CLIENT='02:00:00:00:00:03'
PARAM=DEFAULTS|{'name':'Test','usr_threshold':'2','dif_threshold':'2','max_fail_num':'2'}

class BalanceTests(unittest.TestCase):
    def pair(self):
        a={'mac':A,'ip':'192.0.2.155','state':'run','secure':True,'last_seen':200,
           'station_report_time':200,'session_epoch':'a','radio_ids':[1],'radios':[{'id':1,'band':'2.4 GHz'}],
           'reported_wlans':[{'radio':1,'ssid':'Test'}],
           'stations':{str(i):{'seen':200} for i in range(3)}}
        b=deepcopy(a);b.update(mac=B,ip='192.0.2.153',session_epoch='b',stations={})
        d=Decisions();d.configure({'1':PARAM|{'id':'1','epochs':{A:'a',B:'b'}}})
        probe=decode(encode(9,1,vendor(11,bytes((1,0))+bytes.fromhex(CLIENT.replace(':','')))))
        d.observe(b,probe,200)
        return d,a,b

    def test_wire_mask_signed_rssi_and_disable_preserves_admission(self):
        request=decode(encode(7,1,elements(PARAM)))
        self.assertEqual(request.private(38),[bytes.fromhex('0000006f0000002f')])
        self.assertEqual(request.private(62),[(-75).to_bytes(4,'big',signed=True)])
        off=decode(encode(7,1,elements(PARAM|{'enable':'off'})))
        self.assertEqual(off.private(38),[bytes.fromhex('0000000100000000')]);self.assertFalse(off.private(62))

    def test_reject_limit_and_recovery(self):
        d,a,b=self.pair()
        self.assertEqual([d.decide(a,1,CLIENT,[a,b],201) for _ in range(3)],[39,39,0])
        d.probes[(CLIENT,B,1)]=270;a['last_seen']=b['last_seen']=270
        a['station_report_time']=b['station_report_time']=270
        for s in a['stations'].values():s['seen']=270
        self.assertEqual(d.decide(a,1,CLIENT,[a,b],271),39)

    def test_no_alternative_stale_restarted_unrelated_ssid_allow(self):
        for mutate in (lambda d,a,b:d.probes.clear(),lambda d,a,b:b.update(state='offline'),
                       lambda d,a,b:b.update(session_epoch='new'),lambda d,a,b:b.update(station_report_time=0),
                       lambda d,a,b:b.update(reported_wlans=[{'radio':1,'ssid':'Other'}]),
                       lambda d,a,b:a.update(stations={}),lambda d,a,b:b.update(stations=deepcopy(a['stations']))):
            d,a,b=self.pair();mutate(d,a,b)
            self.assertEqual(d.decide(a,1,CLIENT,[a,b],201),0)

    def test_result39_sent_and_retransmission_does_not_count_twice(self):
        d,a,b=self.pair();sent=[]
        c=Controller({'enabled':True,'allowed_ips':[a['ip'],b['ip']],'dtls':True},lambda *args:sent.append(args),clock=lambda:201)
        a.update(port=1000,cache={},pending=None,private_types=[])
        b.update(port=1001,cache={},pending=None,private_types=[])
        c.peers={(a['ip'],1000):a,(b['ip'],1001):b};c.balance=d
        prefix=bytes((1,1))+bytes.fromhex(CLIENT.replace(':',''))
        packet=encode(9,9,vendor(2,prefix+bytes(4)))
        c.receive((a['ip'],1000),packet,True);c.receive((a['ip'],1000),packet,True)
        reply=decode(sent[-1][1])
        self.assertEqual(int.from_bytes(reply.private(4)[0][8:12],'big'),39)
        self.assertEqual(reply.values(33),[(21).to_bytes(4,'big')])
        self.assertEqual(d.failures[('1',CLIENT)][0],1)
        self.assertEqual(a['association_denials'],1)
        c.receive((a['ip'],1000),encode(9,10,vendor(11,bytes((1,0))+bytes(6))),True)
        self.assertEqual(a['state'],'run')
        self.assertEqual(decode(sent[-1][1]).values(33),[bytes(4)])
        self.assertEqual(a['balance_probe_error'],'invalid station MAC')

    def test_persistent_rules_preflight_ack_and_disable_delete(self):
        with tempfile.TemporaryDirectory() as folder:
            app=Application(ROOT/'web',folder);calls=[]
            ap={'entry_id':'1','mac':A,'ip':'192.0.2.155','session_epoch':'a','management_state':'managed'}
            protected=ap|{'entry_id':'2','mac':B,'ip':'192.0.2.152','management_state':'offline'}
            app.ap_rows=lambda:[ap,protected];app.confirm_action=lambda *a:calls.append(a)
            req={'table':'rule_list','para':PARAM|{'ap_ids':['1','2'],'group_ids':[]}}
            with self.assertRaises(ValueError):app.balance.mutate('add',req)
            self.assertEqual(calls,[]);self.assertEqual(app.balance.rules,{})
            req['para']['ap_ids']=['1'];app.balance.mutate('add',req)
            self.assertEqual(calls[0][0],'192.0.2.155')
            restored=Application(ROOT/'web',folder);self.assertEqual(restored.balance.rules['1']['macs'],[A])
            app.station_policy.enable_admission([A]);self.assertIsNone(app.balance.rules['1']['targets'][A]['epoch'])
            app.balance.reconcile();self.assertEqual(calls[-1][1],'balance')
            app.balance.mutate('delete',{'filter':[{'id':'1'}]})
            self.assertEqual(calls[-1][2]['enable'],'off');self.assertEqual(app.balance.rules,{})

    def test_failed_apply_is_visible_and_does_not_enable_decisions(self):
        with tempfile.TemporaryDirectory() as folder:
            app=Application(ROOT/'web',folder)
            ap={'entry_id':'1','mac':A,'ip':'192.0.2.155','session_epoch':'a','management_state':'managed'}
            app.ap_rows=lambda:[ap]
            def fail(*args):raise ValueError('timeout')
            app.confirm_action=fail
            with self.assertRaises(ValueError):app.balance.mutate('add',{'para':PARAM|{'ap_ids':['1']}})
            self.assertEqual(app.balance.rules['1']['targets'][A]['status'],'failed')
            self.assertEqual(app.service.balance_rules['1']['epochs'],{})

if __name__=='__main__':unittest.main()
