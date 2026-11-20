import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from tplink_ac.web import Application

class SharedImportedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.app=Application(ROOT/'web',self.tmp.name)
        self.app.config.update(enabled=True,allowed_ips=['192.0.2.153','192.0.2.155'])
        self.aps=[{'ip':'192.0.2.'+ip,'mac':'02:00:00:00:00:'+mac,'state':'run','last_seen_seconds':1,
                   'session_epoch':ip,'radio_ids':[1,2]} for ip,mac in [('153','01'),('155','02')]]
        self.app.service.snapshot=lambda:{'aps':self.aps}
        row={'radio_id':'1','apIdx':'0','serv_id':'1','ssid':'Original','key':'original-password',
             'enable':'on','ssidbrd':'1','encryption':'3','auth':'0','cipher':'2','vlan_id':'10','mlo_enable':'0','future':'preserve'}
        self.data={a['mac']:{'error_code':0,'wireless':{'wlan_serv':[{'wlan_serv_1':dict(row)}]}} for a in self.aps}
        self.data[self.aps[1]['mac']]['wireless']['wlan_serv'][0]['wlan_serv_1'].update(vlan_id='20',mlo_enable='1')
        self.writes=[];self.reject=None
        def exchange(mac,action='wireless_read',payload=None):
            if action=='wireless_read':return copy.deepcopy(self.data[mac])
            self.writes.append((mac,copy.deepcopy(payload)))
            if mac==self.reject:return {'error_code':1}
            for item in self.data[mac]['wireless']['wlan_serv']:
                if payload['section'] in item:item[payload['section']].update({k:quote(v,safe='') for k,v in payload['changes'].items()})
            return {'error_code':0}
        self.app.wireless.exchange=exchange
        self.refresh()

    def refresh(self):
        for a in self.aps:self.app.wireless.read_ap(a['mac'])

    def edit(self,changes):
        p=self.app.wireless.profile('1')
        return self.app.wireless.edit({'serv_id':'1','revision':p['revision'],'changes':changes})

    def test_merge_registers_exact_bindings_without_writes_and_survives_restart(self):
        self.assertEqual(len(self.app.profiles),1);self.assertEqual(len(self.app.bindings),2)
        self.assertEqual({b['vlan'] for b in self.app.bindings.values()},{10,20})
        self.assertTrue(all(b['wlan']==1 and b['imported'] and not b['desired'] for b in self.app.bindings.values()))
        self.assertEqual(len([r for r in self.app.radio_rows() if r['bind_status']=='1']),2)
        self.assertFalse(self.writes);self.assertFalse(self.app.wireless.reconcile())
        restored=Application(ROOT/'web',self.tmp.name)
        self.assertEqual(restored.bindings,self.app.bindings);self.assertEqual(restored.profiles,self.app.profiles)

    def test_same_name_different_password_or_auth_does_not_merge(self):
        r=self.data[self.aps[1]['mac']]['wireless']['wlan_serv'][0]['wlan_serv_1']
        r['key']='different-password';self.refresh();self.assertEqual(len(self.app.profiles),2)
        r['key']='original-password';r['auth']='2';self.refresh();self.assertEqual(len(self.app.profiles),2)
        r['auth']='0';self.refresh();self.assertEqual(len(self.app.profiles),1)

    def test_shared_patch_preserves_binding_specific_vlan_mlo_and_unknown_fields(self):
        before=copy.deepcopy(self.data)
        result=self.edit({'ssid':'Renamed','key':'changed-password'})
        self.assertTrue(result['verified']);self.assertEqual(len(self.writes),2)
        for mac,v in self.data.items():
            expected=before[mac]['wireless']['wlan_serv'][0]['wlan_serv_1']|{'ssid':'Renamed','key':'changed-password'}
            actual=v['wireless']['wlan_serv'][0]['wlan_serv_1']
            from urllib.parse import unquote
            self.assertEqual({k:unquote(x) if k in ('ssid','key') else x for k,x in actual.items()},expected)
        self.assertEqual(len(self.app.profiles),1);self.assertEqual(self.app.profiles['1']['ssid'],'Renamed')
        backup=list((self.app.data/'wireless-backups').glob('*shared.json'));self.assertEqual(len(backup),1)
        self.assertEqual(len(json.loads(backup[0].read_text())['tables']),2)

    def test_offline_member_and_changed_baseline_block_every_write(self):
        self.aps[1]['last_seen_seconds']=999
        with self.assertRaisesRegex(ValueError,'离线'):self.edit({'ssid':'New'})
        self.assertFalse(self.writes)
        self.aps[1]['last_seen_seconds']=1
        self.data[self.aps[1]['mac']]['wireless']['wlan_serv'][0]['wlan_serv_1']['vlan_id']='99'
        with self.assertRaisesRegex(ValueError,'不同'):self.edit({'ssid':'New'})
        self.assertFalse(self.writes)

    def test_rejected_second_ap_leaves_actual_split_state_without_retry_or_deletion(self):
        self.reject=self.aps[1]['mac']
        with self.assertRaisesRegex(ValueError,'已确认更新'):self.edit({'ssid':'Changed'})
        self.assertEqual(len(self.writes),2)
        self.assertEqual({p['ssid'] for p in self.app.profiles.values()},{'Original','Changed'})
        self.assertEqual(len(self.app.bindings),2)
        self.assertFalse(self.app.wireless.reconcile());self.assertEqual(len(self.writes),2)

    def test_revision_and_noop_and_legacy_commands_do_not_write(self):
        self.assertFalse(self.edit({'ssid':'Original'})['changed'])
        p=self.app.wireless.profile('1')
        self.app.bindings[('1','257')]['vlan']=11
        with self.assertRaisesRegex(ValueError,'变化'):
            self.app.wireless.edit({'serv_id':'1','revision':p['revision'],'changes':{'ssid':'New'}})
        with self.assertRaises(ValueError):self.app.wireless.change('1')
        with self.assertRaises(ValueError):self.app.wireless.command(next(iter(self.app.bindings.values())),'remove')
        self.assertFalse(self.writes)

    def test_reused_or_removed_section_is_observed_never_recreated(self):
        a=self.aps[1];self.data[a['mac']]['wireless']['wlan_serv']=[]
        self.refresh();self.assertEqual(len(self.app.bindings),1)
        self.aps[0]['session_epoch']='rejoin'
        self.assertFalse(self.app.wireless.reconcile());self.assertFalse(self.writes)

    def test_single_ap_edit_can_merge_into_existing_group(self):
        mac=self.aps[1]['mac']
        self.data[mac]['wireless']['wlan_serv'][0]['wlan_serv_1']['ssid']='Other'
        self.refresh();view=self.app.wireless.read_ap(mac)
        self.assertEqual(len(self.app.profiles),2)
        result=self.app.wireless.edit_ap({'mac':mac,'section':'wlan_serv_1','revision':view['revision'],'changes':{'ssid':'Original'}})
        self.assertTrue(result['verified']);self.assertEqual(len(self.app.profiles),1)
        self.assertEqual(len(self.app.bindings),2);self.assertFalse(result['current']['items'][0]['editable'])

if __name__=='__main__':unittest.main()
