import sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from tplink_ac.service import validate_config,Service
from tplink_ac.adoption import permitted
from tplink_ac.controller import Controller
from tplink_ac.protocol import encode,tlv
from tplink_ac.web import Application

MAC='02:00:00:00:01:04'
class AdoptionTests(unittest.TestCase):
    def cfg(self):
        return validate_config({'enabled':True,'auto_adopt':True,'adopt_subnets':['192.0.2.0/24']})

    def test_subnet_and_overrides(self):
        cfg=self.cfg()
        self.assertTrue(permitted(cfg,'192.0.2.153',MAC))
        self.assertFalse(permitted(cfg,'198.51.100.153',MAC))
        cfg['ap_metadata']={MAC:{'adoption':'block'}}
        cfg['allowed_ips']=['192.0.2.152']
        self.assertFalse(permitted(cfg,'192.0.2.152',MAC))
        self.assertFalse(permitted(cfg,'192.0.2.159',MAC))
        cfg['auto_adopt']=False;cfg['ap_metadata'][MAC]['adoption']='allow'
        self.assertTrue(permitted(cfg,'192.0.2.159',MAC))

    def test_mac_exclusion_across_dtls_ports(self):
        cfg=self.cfg();cfg['ap_metadata']={MAC:{'adoption':'block'}}
        sent=[];c=Controller(cfg,lambda *args:sent.append(args))
        board=tlv(38,bytes(4)+tlv(4,bytes.fromhex(MAC.replace(':',''))))
        c.receive(('192.0.2.152',40000),encode(1,0,board))
        self.assertFalse(sent)
        self.assertFalse(c.allowed(('192.0.2.152',50000)))

    def test_dhcp_address_reuse_does_not_block_different_ap(self):
        cfg=self.cfg();cfg['ap_metadata']={MAC:{'adoption':'block'}}
        c=Controller(cfg,lambda *args:None)
        c.peers[('192.0.2.152',1)]={'mac':MAC,'last_seen':1}
        c.peers[('192.0.2.152',2)]={'mac':'02:00:00:00:01:01','last_seen':2}
        self.assertFalse(c.allowed(('192.0.2.152',1)))
        self.assertTrue(c.allowed(('192.0.2.152',2)))
        self.assertTrue(c.allowed(('192.0.2.152',50000)))

    def test_policy_change_cancels_pending_and_closes_only_excluded(self):
        cfg=self.cfg();s=Service();s.engine=Controller(cfg,lambda *args:None)
        closed=[]
        class Session:
            def __init__(self,ip): self.ip=ip
            def close(self):closed.append(self.ip)
        for ip,mac in [('192.0.2.152',MAC),('192.0.2.155','02:00:00:00:01:01')]:
            s.engine.peers[(ip,1)]={'mac':mac,'state':'run','pending':{'id':ip,'action':'apply'},'last_seen':s.engine.clock()}
            s.secure[(ip,1)]={'session':Session(ip)}
        cfg['ap_metadata']={MAC:{'adoption':'block'}};s.update_policy(cfg)
        self.assertEqual(closed,['192.0.2.152'])
        self.assertEqual(s.engine.results['192.0.2.152']['status'],'cancelled')
        self.assertEqual(s.engine.peers[('192.0.2.155',1)]['state'],'run')

    def test_names_and_notes_without_adoption_persist(self):
        with tempfile.TemporaryDirectory() as folder:
            a=Application(ROOT/'web',folder);a.config=self.cfg()
            a.config['ap_metadata']={MAC:{'adoption':'block'}}
            a.service.snapshot=lambda:{'aps':[{'ip':'192.0.2.152','mac':MAC,'state':'observed','last_seen_seconds':1}]}
            def forbidden(*args):self.fail('metadata must not send AP commands')
            a.service.action=forbidden
            ident=a.ap_rows()[0]['entry_id']
            a.ds({'method':'set','apmng_set':{'table':'ap_list','filter':[{'entry_id':ident}],'para':{'entry_name':'测试区域','remark':'测试 AP'}}})
            row=a.ap_rows()[0];self.assertEqual(row['entry_name'],'测试区域');self.assertEqual(row['management_label'],'不接管')
            restored=Application(ROOT/'web',folder)
            self.assertEqual(restored.config['ap_metadata'][MAC],{'name':'测试区域','remark':'测试 AP','adoption':'block'})
            self.assertEqual(restored.ids,a.ids)
            a.save_ap_settings({'auto_adopt':False})
            self.assertFalse(a.config['auto_adopt'])

    def test_validation(self):
        for patch in ({'auto_adopt':'yes'},{'adopt_subnets':['0.0.0.0/0']},{'ap_metadata':{MAC:{'adoption':'yes'}}},{'ap_metadata':{MAC:{'name':'x'*65}}}):
            with self.assertRaises(ValueError):validate_config(self.cfg()|patch)

if __name__=='__main__':unittest.main()
