import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from tplink_ac.web import Application


class GroupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.app=Application(ROOT/'web',self.tmp.name)
        self.app.config.update(enabled=True,auto_adopt=True,adopt_subnets=['192.0.2.0/24'])
        self.aps=[{'ip':'192.0.2.155','mac':'02:00:00:00:00:01','state':'run','last_seen_seconds':0,'radio_ids':[1]}]
        self.app.service.snapshot=lambda:{'aps':self.aps,'running':True,'events':[]}

    def write(self,method,para=None,ids=None):
        request={'table':'group_list'}
        if para is not None:request['para']=para
        if ids is not None:request['filter']=[{'group_id':ids}]
        return self.app.ds({'method':method,'apmng_set':request})

    def test_membership_persists_by_mac_and_counts(self):
        self.write('add',{'name':'测试'})
        ap=self.app.ap_rows()[0]
        self.app.ds({'method':'set','apmng_set':{'table':'ap_list','filter':[{'entry_id':ap['entry_id']}],'para':{'group_id':'2'}}})
        self.aps[0]['ip']='192.0.2.156'
        self.assertEqual(self.app.ap_rows()[0]['group_name'],'测试')
        self.assertEqual(self.app.groups.rows()[1]['active'],'1')
        again=Application(ROOT/'web',self.tmp.name)
        self.assertEqual(again.groups.group_for(self.aps[0]),'2')
        with self.assertRaises(ValueError):self.write('delete',ids=['2'])
        self.app.groups.assign(self.app.ap_rows(),'1')
        self.write('delete',ids=['2'])
        self.assertEqual(len(self.app.groups.rows()),1)

    def test_auto_strategy_and_manual_override(self):
        self.write('add',{'name':'自动','strategy_enable':'on','start_ip':'192.0.2.150','end_ip':'192.0.2.160'})
        self.assertEqual(self.app.ap_rows()[0]['group_id'],'2')
        before=json.loads(json.dumps(self.app.groups.state))
        with self.assertRaises(ValueError):self.write('add',{'name':'重叠','strategy_enable':'on','start_ip':'192.0.2.155','end_ip':'192.0.2.170'})
        self.assertEqual(self.app.groups.state,before)
        self.app.groups.assign(self.app.ap_rows(),'1')
        self.assertEqual(self.app.ap_rows()[0]['group_id'],'1')

    def test_validation_and_topology(self):
        with self.assertRaises(ValueError):self.write('delete',ids=['1'])
        with self.assertRaises(ValueError):self.write('add',{'name':'默认分组'})
        with self.assertRaises(ValueError):self.write('add',{'name':'测试','fake_field':'on'})
        self.write('add',{'name':'房间'})
        self.app.groups.assign(self.app.ap_rows(),'2')
        topo=self.app.monitor.topology()
        self.assertIn('房间',[n['devName'] for n in topo['devList']])
        self.assertNotIn('默认分组',[n['devName'] for n in topo['devList']])


if __name__=='__main__':unittest.main()
