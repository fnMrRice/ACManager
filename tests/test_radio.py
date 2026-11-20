import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from tplink_ac.radio import radio_elements
from tplink_ac.protocol import parse_tlvs
from tplink_ac.web import Application


class RadioTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.app=Application(ROOT/'web',self.tmp.name)
        self.app.config.update(enabled=True,allowed_ips=['192.0.2.155'])
        self.ap={'ip':'192.0.2.155','mac':'02:00:00:00:00:01','state':'run','last_seen_seconds':1,
            'radio_ids':[1], 'radios':[{'id':1,'band':'2.4 GHz','min_power':3,'max_power':24}],
            'radio_states':{'1':'on'},
            'radio_report_time':time.monotonic(),'radio_statistics':{'1':{'channel':6,'bandwidth':1}}}
        self.operations={};self.calls=[]
        self.app.service.snapshot=lambda:{'aps':[self.ap],'operations':self.operations}
        def action(ip,action,params):
            self.calls.append((ip,action,params));ident=str(len(self.calls))
            self.operations[ident]={'status':'acknowledged'}
            if 'channel' in params:
                self.ap['radio_statistics']['1']['channel']=params['channel']
                self.ap['radio_report_time']=time.monotonic()+1
            return {'id':ident}
        self.app.service.action=action

    def test_packet_does_not_overwrite_unselected_settings(self):
        packet=radio_elements(self.ap,{'radio':1,'channel':11})
        self.assertEqual(parse_tlvs(packet),[(31,b'\x01\x01'),(1028,bytes.fromhex('01000b0200000000'))])
        packet=radio_elements(self.ap,{'radio':1,'power_dbm':20})
        self.assertEqual(parse_tlvs(packet),[(31,b'\x01\x01'),(1041,b'\x01\x00\x00\x14')])
        self.assertEqual(parse_tlvs(radio_elements(self.ap,{'radio':1,'rf_state':'off'})),[(31,b'\x01\x02')])
        for params in ({'radio':2,'channel':6},{'radio':1,'channel':36},
                       {'radio':1,'power_dbm':25},{'radio':1,'bandwidth':5},
                       {'radio':1,'channel':6.5},{'radio':1,'channel':6,'rf_state':'off'}):
            with self.assertRaises(ValueError):radio_elements(self.ap,params)

    def test_ack_persistence_mac_and_readback(self):
        row=self.app.radios.rows()[0]
        self.assertEqual(row['channel'],'6')
        self.app.radios.change([row['rf_id']],{'channel':11})
        self.assertEqual(self.calls[0][0],'192.0.2.155')
        again=Application(ROOT/'web',self.tmp.name)
        self.assertEqual(again.radios.settings[self.ap['mac']]['1']['channel'],11)
        # Desired channel is not masqueraded as AP readback.
        self.assertEqual(self.app.radios.rows()[0]['channel'],'11')
        self.ap['radio_report_time']=0
        self.assertEqual(self.app.radios.rows()[0]['channel'],'---')

    def test_rejection_and_batch_preflight(self):
        with self.assertRaises(ValueError):self.app.radios.change(['17','999'],{'channel':11})
        self.assertFalse(self.calls)
        self.app.confirm_action=lambda *args: (_ for _ in ()).throw(ValueError('rejected'))
        with self.assertRaises(ValueError):self.app.radios.change(['17'],{'channel':11})
        self.assertFalse(self.app.radios.settings)

    def test_csv_preview_and_entire_file_preflight(self):
        text=self.app.radios.csv().decode('utf8')
        plan=self.app.radios.import_plan(text)
        self.assertEqual(plan[0]['mac'],self.ap['mac'])
        self.assertEqual(self.calls,[])
        with self.assertRaises(ValueError):self.app.radios.import_csv(text+'02:00:00:00:00:99,1,6,,on\r\n')
        self.assertEqual(self.calls,[])
        with self.assertRaises(ValueError):self.app.radios.import_plan(text+text.splitlines()[1]+'\r\n')
        with self.assertRaises(ValueError):self.app.radios.import_plan('wrong,headers\r\n')


if __name__=='__main__':unittest.main()
