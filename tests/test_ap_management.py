import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from tplink_ac.web import Application
from tplink_ac.ap_management import control,export_csv
from tplink_ac.controller import Controller
from tplink_ac.protocol import decode,encode,tlv

class ApManagementTests(unittest.TestCase):
    def test_reset_wire_and_ack(self):
        for action,expected in (('reboot',[]),('factory_reset',[bytes.fromhex('00000003')])):
            sent=[];c=Controller({'enabled':True,'dtls':True,'allowed_ips':['192.0.2.155']},lambda *a:sent.append(a),clock=lambda:1)
            peer=('192.0.2.155',1000)
            c.peers[peer]={'ip':peer[0],'mac':'02:00:00:00:00:01','state':'run','last_seen':0,
                'secure':True,'pending':None,'cache':{},'radio_ids':[1],'private_types':[]}
            p=c.operation(peer[0],action);packet=decode(sent[-1][1])
            self.assertEqual(packet.kind,17);self.assertEqual(packet.private(35),expected)
            c.receive(peer,encode(18,p['sequence'],tlv(33,bytes(4))),True)
            self.assertEqual(c.peers[peer]['state'],'restarting')

    def test_preflight_and_confirmed_reset_forgets_owned_config(self):
        with tempfile.TemporaryDirectory() as directory:
            app=Application(ROOT/'web',directory);calls=[]
            mac='02:00:00:00:00:01'
            app.ap_rows=lambda:[{'entry_id':'1','mac':mac,'ip':'192.0.2.155','management_state':'managed'},
                {'entry_id':'2','mac':'02:00:00:00:00:02','ip':'192.0.2.152','management_state':'offline'}]
            app.confirm_action=lambda *a:calls.append(a)
            app.bindings[('1','257')]={'mac':mac,'desired':True,'active':True}
            with self.assertRaises(ValueError):control(app,['1','2'],'reboot')
            self.assertEqual(calls,[])
            control(app,['1'],'factory_reset')
            self.assertFalse(app.bindings)
            self.assertEqual(calls,[('192.0.2.155','factory_reset')])
            self.assertIn('192.0.2.155',export_csv(app).decode('utf8'))

if __name__=='__main__':unittest.main()
