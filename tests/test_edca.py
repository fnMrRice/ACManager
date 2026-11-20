import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from tplink_ac.edca import DEFAULTS,elements
from tplink_ac.protocol import decode,encode
from tplink_ac.web import Application

class EdcaTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.app=Application(ROOT/'web',self.temp.name)
        self.mac='02:00:00:00:00:01'
        self.ap={'entry_id':'1','mac':self.mac,'ip':'192.0.2.155','entry_name':'Test',
            'radio_ids':[1,2],'session_epoch':'first','management_state':'managed'}
        self.other=self.ap|{'entry_id':'2','mac':'02:00:00:00:00:02','ip':'192.0.2.152','management_state':'offline'}
        self.app.ap_rows=lambda:[self.ap,self.other];self.calls=[]
        self.app.confirm_action=lambda *a:self.calls.append(a)
        self.body={'name':'test','enable':'on','targets':[{'mac':self.mac,'radio':1}],'parameters':DEFAULTS}

    def test_codec_limits_and_order(self):
        wire=decode(encode(7,1,elements(self.ap,{'radio':1,'enable':'on','parameters':DEFAULTS}))).private(146)[0]
        self.assertEqual(len(wire),42)
        self.assertEqual(wire[:12],bytes.fromhex('0101010203002f010304005e'))
        with self.assertRaises(ValueError): elements(self.ap,{'radio':1,'enable':'on','parameters':DEFAULTS|{'ap_vo':[1,5,2,47]}})

    def test_preflight_conflict_and_rejoin(self):
        with self.assertRaises(ValueError):self.app.edca.change(self.body|{'targets':self.body['targets']+[{'mac':self.other['mac'],'radio':1}]})
        self.assertFalse(self.calls);self.assertFalse(self.app.edca.rules)
        result=self.app.edca.change(self.body);self.assertEqual(result['id'],'1')
        with self.assertRaises(ValueError):self.app.edca.change(self.body|{'name':'another'})
        restored=Application(ROOT/'web',self.temp.name);self.assertIn('1',restored.edca.rules)
        self.app.edca.reconcile();self.assertEqual(len(self.calls),1)
        self.ap['session_epoch']='second';self.app.edca.reconcile();self.assertEqual(len(self.calls),2)
        self.app.edca.delete(['1']);self.assertFalse(self.app.edca.rules)
        self.assertEqual(self.calls[-1][2]['enable'],'off')
        self.assertTrue(all(c[0]=='192.0.2.155' for c in self.calls))

    def test_rejected_rule_is_visible_not_success(self):
        def fail(*args):raise ValueError('AP rejected')
        self.app.confirm_action=fail
        with self.assertRaisesRegex(ValueError,'未确认'):self.app.edca.change(self.body)
        self.assertEqual(self.app.edca.rows()[0]['deployment'],'0/1 已确认')
        self.assertEqual(self.app.edca.rows()[0]['targets'][0]['status'],'failed')

if __name__=='__main__':unittest.main()
