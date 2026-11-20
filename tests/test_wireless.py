import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from tplink_ac.web import Application
from tplink_ac.protocol import decode,encode,identity,tlv,delete_wlan_elements,wlan_report,vendor
import struct
import time

class WirelessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.app=Application(ROOT/'web',self.temp.name)
        self.app.config['allowed_ips']=['192.0.2.155']
        self.app.config['enabled']=True
        self.aps=[dict(ip='192.0.2.'+ip,mac='02:00:00:00:00:'+ip,
                       state='run',last_seen_seconds=1,radio_ids=[1,2],
                       radios=[{'id':1,'band':'2.4 GHz','max_ssids':7},{'id':2,'band':'5 GHz','max_ssids':7}],
                       reported_wlans=[]) for ip in ('155','152')]
        self.operations={};self.calls=[];self.reject_at=None
        self.app.service.snapshot=lambda:{'aps':self.aps,'operations':self.operations}
        def action(ip,action,params):
            self.calls.append((ip,action,params));ident=str(len(self.calls))
            self.operations[ident]={'status':'rejected' if len(self.calls)==self.reject_at else 'acknowledged','result_code':0}
            return {'id':ident}
        self.app.service.action=action
        self.profile={'ssid':'Lab','key':'password','encryption':'1','auth':'2','cipher':'2','enable':'on'}
        self.app.ds({'method':'add','apmng_wserv':{'table':'wlan_serv','para':self.profile}})
        self.app.ap_rows()

    def bind(self,enabled,radios=None):
        radios=radios or ['257']
        return self.app.ds({'method':'set','apmngWserv':{'table':'radio_bind_list','filter':[{'servId':'1'}],
            'para':{'radioId':radios,'bindStatus':str(enabled),'bindVlanType':'single_vlan','vlanId':['0']*len(radios)}}})

    def test_binding_persistence_and_manual_unbind_intent(self):
        self.assertEqual(self.bind(1)['status'],'acknowledged')
        restored=Application(ROOT/'web',self.temp.name)
        self.assertTrue(restored.bindings[('1','257')]['active'])
        self.assertEqual(restored.ids,self.app.ids)
        self.bind(0)
        count=len(self.calls)
        self.app.wireless.change('1',self.profile|{'desc':'changed'})
        self.assertEqual(len(self.calls),count)
        self.assertFalse(self.app.bindings[('1','257')]['desired'])
        self.bind(1)
        self.assertEqual(self.calls[-1][2]['wlan'],7)

    def test_entire_batch_preflight_protects_152(self):
        with self.assertRaisesRegex(ValueError,'允许管理'): self.bind(1,['257','513'])
        self.assertEqual(self.calls,[])
        self.assertTrue(all(int(r['radio_id'])//256==1 for r in self.app.radio_rows()))

    def test_rejected_ack_not_success(self):
        self.reject_at=1
        with self.assertRaisesRegex(ValueError,'未确认'): self.bind(1)
        self.assertFalse(self.app.bindings[('1','257')]['active'])

    def test_external_inventory_is_not_slot_map(self):
        self.aps[0]['reported_wlans']=[{'radio':1,'ssid':'Existing'}]
        with self.assertRaisesRegex(ValueError,'空闲编号'): self.bind(1)
        self.assertEqual(self.calls,[])

    def test_reported_slots_preserve_external_services(self):
        self.aps[0].update(reported_wlans=[{'radio':1,'ssid':'Existing'}],
            radio_report_time=time.monotonic(),reported_bssids={'1:7':'02:00:00:00:00:07'})
        self.bind(1)
        self.assertEqual(self.calls[-1][2]['wlan'],6)

    def test_rejoin_restores_only_owned_unoccupied_slot(self):
        self.bind(1)
        self.aps[0].update(session_epoch='new-session',radio_report_time=time.monotonic(),
            reported_bssids={'1:1':'02:00:00:00:00:01'})
        before=len(self.calls)
        self.app.wireless.reconcile()
        self.assertEqual(len(self.calls),before+1)
        self.assertEqual(self.calls[-1][2]['wlan'],7)
        self.assertTrue(all(c[0]=='192.0.2.155' for c in self.calls))
        self.app.wireless.reconcile()
        self.assertEqual(len(self.calls),before+1)
        self.aps[0]['session_epoch']='third-session'
        self.aps[0]['reported_bssids']['1:7']='02:00:00:00:00:07'
        self.app.wireless.retry_after.clear()
        self.app.wireless.reconcile()
        self.assertEqual(len(self.calls),before+1)
        self.assertEqual(self.app.bindings[('1','257')]['status'],'slot_conflict')
        with self.assertRaisesRegex(ValueError,'占用'):
            self.app.wireless.change('1',self.profile|{'ssid':'Changed'})
        self.assertEqual(len(self.calls),before+1)

    def test_retained_owned_ssid_is_observed_without_overwrite(self):
        self.aps[0]['session_epoch']='before'
        self.bind(1)
        self.aps[0].update(session_epoch='after',radio_report_time=time.monotonic(),
            reported_wlans=[{'radio':1,'ssid':'Lab'}],reported_bssids={'1:7':'02:00:00:00:00:07'})
        before=len(self.calls)
        self.app.wireless.reconcile()
        binding=self.app.bindings[('1','257')]
        self.assertEqual(binding['status'],'retained')
        self.assertTrue(binding['active'])
        self.assertEqual(len(self.calls),before)
        self.aps[0]['session_epoch']='another'
        self.aps[0]['reported_bssids']['1:7']='02:00:00:00:00:08'
        self.app.wireless.retry_after.clear();self.app.wireless.reconcile()
        self.assertEqual(binding['status'],'slot_conflict')
        self.assertEqual(len(self.calls),before)

    def test_disable_enable_and_edit_rollback(self):
        self.bind(1,['257','258'])
        self.app.wireless.change('1',self.profile|{'enable':'off'})
        self.assertTrue(all(b['desired'] and not b['active'] for b in self.app.bindings.values()))
        self.app.wireless.change('1',self.profile)
        self.reject_at=len(self.calls)+4 # second radio rejects updated profile
        with self.assertRaisesRegex(ValueError,'未确认'):
            self.app.wireless.change('1',self.profile|{'ssid':'Changed'})
        self.assertEqual(self.app.profiles['1']['ssid'],'Lab')
        self.assertTrue(all(b['active'] for b in self.app.bindings.values()))
        self.assertEqual([c[2].get('ssid') for c in self.calls[-3:] if c[1]=='apply'],['Lab','Lab'])

    def test_unbound_not_shown_from_stale_report(self):
        self.bind(1)
        self.aps[0]['reported_wlans']=[{'radio':1,'ssid':'Lab'}]
        self.bind(0)
        self.assertFalse(self.app.ssid_rows())

    def test_inventory_source_and_read_never_write_or_infer_password(self):
        self.aps[0]['reported_wlans']=[{'radio':1,'ssid':'Existing'}]
        view=self.app.api('wireless/inventory',{})
        self.assertEqual(len(view['items']),1)
        row=view['items'][0]
        self.assertEqual(row['source'],'ap_report')
        self.assertEqual(row['password_state'],'未读取')
        self.assertIsNone(row['serv_id']);self.assertFalse(row['editable'])
        self.assertNotIn('key',row);self.assertNotIn('wlan',row)
        with self.assertRaisesRegex(ValueError,'完整配置'):
            self.app.api('wireless/edit',{'serv_id':None,'changes':{'key':'password'}})
        self.assertEqual(self.calls,[])

    def test_edit_preserves_unspecified_security_vlan_and_bindings(self):
        self.profile.update(ssidbrd='0',isolate='1',key_update_intv='3600',desc='keep')
        self.app.wireless.change('1',self.app.profiles['1']|self.profile)
        self.bind(1)
        before=self.app.api('wireless/profile',{'serv_id':'1'})
        self.assertEqual(before['source'],'controller_saved')
        self.assertEqual(before['profile']['key'],'password')
        self.app.api('wireless/edit',{'serv_id':'1','revision':before['revision'],'changes':{'ssid':'Renamed'}})
        sent=self.calls[-1][2]
        self.assertEqual(sent['key'],'password');self.assertTrue(sent['hidden']);self.assertTrue(sent['isolate'])
        self.assertEqual(sent['key_interval'],'3600');self.assertEqual(sent['wlan'],7)
        self.assertEqual(self.app.profiles['1']['desc'],'keep')
        count=len(self.calls)
        fresh=self.app.api('wireless/profile',{'serv_id':'1'})
        self.app.api('wireless/edit',{'serv_id':'1','revision':fresh['revision'],'changes':{'ssid':'Renamed'}})
        self.assertEqual(len(self.calls),count)
        with self.assertRaisesRegex(ValueError,'变化'):
            self.app.api('wireless/edit',{'serv_id':'1','revision':before['revision'],'changes':{'ssid':'Old'}})
        self.assertEqual(len(self.calls),count)

    def test_batch_preview_is_read_only_and_stale_slots_rejected(self):
        self.aps[0].update(reported_wlans=[{'radio':1,'ssid':'Existing'}],
            radio_report_time=time.monotonic(),reported_bssids={'1:7':'02:00:00:00:00:07'})
        request={'table':'radio_bind_list','filter':[{'servId':'1'}],
                 'para':{'radioId':['257'],'bindStatus':'1','bindVlanType':'single_vlan','vlanId':['0']}}
        plan=self.app.api('wireless/bind-preview',{'request':request})
        self.assertEqual(plan['items'][0]['wlan'],6);self.assertEqual(self.calls,[])
        self.assertEqual(self.app.bindings,{})
        self.aps[0]['reported_bssids']['1:6']='02:00:00:00:00:06'
        with self.assertRaisesRegex(ValueError,'变化'):
            self.app.api('wireless/bind',{'request':request,'revision':plan['revision']})
        self.assertEqual(self.calls,[])
        plan=self.app.api('wireless/bind-preview',{'request':request})
        self.app.api('wireless/bind',{'request':request,'revision':plan['revision']})
        self.assertEqual(self.calls[-1][2]['wlan'],5)

    def test_duplicate_external_ssid_never_adopted_or_overwritten(self):
        self.aps[0]['reported_wlans']=[{'radio':1,'ssid':'Lab'}]
        with self.assertRaisesRegex(ValueError,'同名'): self.bind(1)
        self.assertEqual(self.calls,[])
        self.aps[0]['reported_wlans']=[];self.bind(1)
        self.aps[0]['reported_wlans']=[{'radio':1,'ssid':'Existing'}]
        count=len(self.calls)
        with self.assertRaisesRegex(ValueError,'同名'):
            self.app.wireless.change('1',self.app.profiles['1']|{'ssid':'Existing'})
        self.assertEqual(len(self.calls),count)

    def test_reused_owned_slot_rejected_before_any_deletion(self):
        self.bind(1)
        self.app.bindings[('1','257')]['confirmed_bssid']='02:00:00:00:00:07'
        self.aps[0]['reported_bssids']={'1:7':'02:00:00:00:00:08'}
        count=len(self.calls)
        with self.assertRaisesRegex(ValueError,'BSSID'):
            self.app.wireless.change('1',self.app.profiles['1']|{'key':'another-password'})
        self.assertEqual(len(self.calls),count)

class WirelessCodecTests(unittest.TestCase):
    def test_open_and_psk_security_modes(self):
        from tplink_ac.protocol import wlan_elements
        for dialect in (9,99):
            packet=decode(encode(7,0,wlan_elements('Open','',dialect=dialect,encryption=0)))
            self.assertEqual(packet.private(dialect),[bytes.fromhex('010100000040030000')])
            packet=decode(encode(7,0,wlan_elements('Mixed','password',dialect=dialect,auth=3,cipher=0,key_interval=3600)))
            self.assertEqual(packet.private(dialect)[0][9:17],struct.pack('!BBIH',3,0,3600,8))
        for kwargs in ({'cipher':3},{'key_interval':29},{'key_interval':604801},{'encryption':2}):
            with self.assertRaises(ValueError): wlan_elements('Bad','password',**kwargs)

    def test_capability_dialect_and_remove(self):
        for word,expected in ((0,'legacy9'),(1,'modern99'),(0x80000001,'extended')):
            info=identity(decode(encode(3,0,tlv(50,struct.pack('!4I',0,word,0,0)))))
            self.assertEqual(info['wireless_dialect'],expected)
        self.assertEqual(delete_wlan_elements(1,7),tlv(1027,b'\x01\x07'))

    def test_inventory(self):
        packet=encode(7,0,vendor(30,struct.pack('!II',1,1)+b'\x01Test'+bytes(28)))
        self.assertEqual(wlan_report(decode(packet)),[{'radio':1,'ssid':'Test'}])

if __name__=='__main__':unittest.main()
