import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from tplink_ac.web import Application
from tplink_ac.features import band_elements,DEFAULT_BAND
from tplink_ac.protocol import decode,encode

class FeaturesTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.app=Application(ROOT/'web',self.temp.name)
        self.app.config.update(enabled=True,auto_adopt=True,adopt_subnets=['192.0.2.0/24'])
        self.ap={'mac':'02:00:00:00:00:01','ip':'192.0.2.155','state':'run','last_seen_seconds':0,
            'radios':[{'id':1,'band':'2.4 GHz'},{'id':2,'band':'5 GHz'}],'session_epoch':'first'}
        self.other=self.ap|{'mac':'02:00:00:00:00:02','ip':'192.0.2.152','radios':[{'id':1,'band':'2.4 GHz'}]}
        self.app.service.snapshot=lambda:{'aps':[self.ap,self.other]}
        self.calls=[]
        self.app.confirm_action=lambda *args:self.calls.append(args)

    def test_wire_and_full_batch_validation(self):
        data=decode(encode(7,0,band_elements(self.ap,DEFAULT_BAND|{'enable':'on'})))
        self.assertEqual(data.private(58),[bytes((1,20,4,10))])
        with self.assertRaises(ValueError): self.app.features.change([self.ap['mac'],self.other['mac']],DEFAULT_BAND)
        self.assertEqual(self.calls,[])
        with self.assertRaises(ValueError): band_elements(self.ap,DEFAULT_BAND|{'dif_threshold':'4.5'})

    def test_persist_rejoin_follows_mac_not_ip(self):
        self.app.features.change([self.ap['mac']],DEFAULT_BAND|{'enable':'on'})
        restored=Application(ROOT/'web',self.temp.name)
        self.assertEqual(restored.features.targets[self.ap['mac']]['settings']['enable'],'on')
        self.app.features.reconcile();self.assertEqual(len(self.calls),1)
        self.ap.update(session_epoch='second',ip='192.0.2.160')
        self.app.features.reconcile();self.assertEqual(self.calls[-1][0],'192.0.2.160')
        self.assertEqual(len(self.calls),2)
        self.assertFalse(any(c[0]=='192.0.2.152' for c in self.calls))
        self.assertEqual(self.app.features.view()['aps'][0]['status'],'acknowledged')

if __name__=='__main__':unittest.main()
