import json,struct,sys,unittest,tempfile,copy
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from tplink_ac.readback import query,response,QUERY,patch,table
from tplink_ac.protocol import encode,decode,tlv,vendor,ProtocolError,VENDOR
from tplink_ac.controller import Controller
from tplink_ac.service import DEFAULTS

class ReadbackTests(unittest.TestCase):
    def test_wire_format_and_only_fixed_get_query(self):
        raw=decode(encode(7,1,query(123))).private(131)[0]
        ident,size,flag=struct.unpack_from('!IIB',raw)
        self.assertEqual((ident,flag),(123,1));self.assertEqual(size,len(raw)-9)
        self.assertEqual(json.loads(raw[9:]),QUERY);self.assertEqual(QUERY['method'],'get')
        for ident in (0,-1,True,'123',2**32):
            with self.assertRaises(ValueError):query(ident)

    def ready(self):
        self.sent=[];self.now=0;self.peer=('127.0.0.1',10000)
        self.c=Controller(DEFAULTS|{'enabled':True,'allowed_ips':['127.0.0.1'],'dtls':True},lambda *x:self.sent.append(x),lambda:self.now)
        board=tlv(38,struct.pack('!I',VENDOR)+tlv(4,bytes.fromhex('020000000001')))
        for kind,fields in ((1,board+tlv(1048,b'\x01\0\0\0\x01')),(3,board+tlv(35,b'S'*16)),(5,b''),(11,b'')):
            self.c.receive(self.peer,encode(kind,kind,fields),kind!=1)
        self.c.operation(self.peer[0],'wireless_read',{'request_id':123})

    def test_private_correlated_reply_not_public_telemetry(self):
        self.ready();data=json.dumps({'wireless':{'key':'private-password'}}).encode()
        reply=vendor(131,struct.pack('!IIB',123,len(data),0)+data)
        self.c.receive(self.peer,encode(9,44,reply),True)
        self.assertEqual(self.c.read_requests[123]['result']['data']['wireless']['key'],'private-password')
        self.assertNotIn('private-password',str(self.c.status()))
        self.assertEqual(decode(self.sent[-1][1]).kind,10)

    def test_malformed_reply_does_not_disconnect_and_timeout_removes_secret(self):
        self.ready()
        self.c.receive(self.peer,encode(9,44,vendor(131,struct.pack('!IIB',123,99,0)+b'{}')),True)
        self.assertIn('error',self.c.read_requests[123]['result'])
        self.assertEqual(self.c.peers[self.peer]['state'],'run')
        self.now=31;self.c.tick();self.assertNotIn(123,self.c.read_requests)

    def test_wrong_session_reply_ignored(self):
        self.ready();self.c.read_requests[123]['epoch']='wrong'
        self.c.receive(self.peer,encode(9,44,vendor(131,struct.pack('!IIB',123,2,0)+b'{}')),True)
        self.assertNotIn('result',self.c.read_requests[123])

    def test_partial_patch_wire_contains_only_selected_fields(self):
        raw=decode(encode(7,1,patch(12,'wlan_serv_9',{'ssid':'名字 %','key':'pass%word'}))).private(131)[0]
        self.assertEqual(json.loads(raw[9:]),{'method':'set','wireless':{'wlan_serv_9':{'ssid':'%E5%90%8D%E5%AD%97%20%25','key':'pass%25word'}}})
        for changes in ({'encryption':'0'},{'key':''},{'ssid':''}):
            with self.assertRaises(ValueError):patch(12,'wlan_serv_9',changes)

class ApEditingTests(unittest.TestCase):
    def setUp(self):
        from tplink_ac.web import Application
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.app=Application(Path(__file__).resolve().parents[1]/'web',self.tmp.name)
        self.app.config['allowed_ips']=['192.0.2.155']
        self.app.config['enabled']=True
        self.mac='02:00:00:00:00:01';self.calls=[]
        self.app.service.snapshot=lambda:{'aps':[{'ip':'192.0.2.155','mac':self.mac,'state':'run','last_seen_seconds':1,'session_epoch':'session','radio_ids':[1,2]}]}
        row={'radio_id':'1','apIdx':'0','serv_id':'1','ssid':'Original%25SSID','key':'original%25password','enable':'on','ssidbrd':'0','encryption':'3','auth':'0','cipher':'2','vlan_id':'12','mlo_enable':'1','unknown_future_flag':'keep'}
        self.data={'error_code':0,'wireless':{'wlan_serv':[{'wlan_serv_1':row},{'wlan_serv_9':row|{'radio_id':'2','serv_id':'9','ssid':'Other'}}]}}
        def exchange(mac,action='wireless_read',payload=None):
            self.assertEqual(mac,self.mac)
            if action=='wireless_read':return copy.deepcopy(self.data)
            self.calls.append(payload)
            from urllib.parse import quote
            for item in self.data['wireless']['wlan_serv']:
                if payload['section'] in item:item[payload['section']].update({k:quote(v,safe='') for k,v in payload['changes'].items()})
            return {'error_code':0}
        self.app.wireless.exchange=exchange

    def test_read_and_edit_preserve_original_other_fields_and_other_wlan(self):
        view=self.app.wireless.read_ap(self.mac)
        self.assertEqual(view['items'][0]['ssid'],'Original%SSID');self.assertEqual(view['items'][0]['key'],'original%password')
        old=copy.deepcopy(self.data);self.assertFalse(self.calls)
        result=self.app.wireless.edit_ap({'mac':self.mac,'section':'wlan_serv_1','revision':view['revision'],'changes':{'ssid':'New'}})
        self.assertTrue(result['verified']);self.assertEqual(self.calls,[{'section':'wlan_serv_1','changes':{'ssid':'New'}}])
        self.assertEqual(self.data['wireless']['wlan_serv'][1],old['wireless']['wlan_serv'][1])
        self.assertEqual(self.data['wireless']['wlan_serv'][0]['wlan_serv_1'],old['wireless']['wlan_serv'][0]['wlan_serv_1']|{'ssid':'New'})
        backup=list((self.app.data/'wireless-backups').glob('*.json'));self.assertEqual(len(backup),1)
        self.assertEqual(json.loads(backup[0].read_text())['rows']['wlan_serv_1']['key'],'original%password')

    def test_stale_original_blocks_write(self):
        view=self.app.wireless.read_ap(self.mac)
        self.data['wireless']['wlan_serv'][0]['wlan_serv_1']['vlan_id']='99'
        with self.assertRaisesRegex(ValueError,'变化'):
            self.app.wireless.edit_ap({'mac':self.mac,'section':'wlan_serv_1','revision':view['revision'],'changes':{'ssid':'New'}})
        self.assertFalse(self.calls)

    def test_original_noop_sends_no_write(self):
        view=self.app.wireless.read_ap(self.mac)
        result=self.app.wireless.edit_ap({'mac':self.mac,'section':'wlan_serv_1','revision':view['revision'],'changes':{'ssid':'Original%SSID'}})
        self.assertFalse(result['changed']);self.assertFalse(self.calls)

    def test_owned_edit_response_remains_editable_and_restore_matches(self):
        self.data['wireless']['wlan_serv'][0]['wlan_serv_1'].update(encryption='1',auth='2')
        self.app.profiles['1']={'ssid':'Original%SSID','key':'original%password','encryption':'1','auth':'2','cipher':'2'}
        self.app.bindings[('1','257')]={'mac':self.mac,'radio':1,'wlan':1,'vlan':12,'active':True,'desired':True}
        before=self.app.wireless.read_ap(self.mac)
        edited=self.app.wireless.edit_ap({'mac':self.mac,'section':'wlan_serv_1','revision':before['revision'],'changes':{'ssid':'New'}})
        self.assertTrue(edited['current']['items'][0]['editable'])
        restored=self.app.wireless.edit_ap({'mac':self.mac,'section':'wlan_serv_1','revision':edited['current']['revision'],'changes':{'ssid':'Original%SSID'}})
        self.assertEqual(restored['current']['items'],before['items'])

class AutomaticImportTests(unittest.TestCase):
    setUp=ApEditingTests.setUp

    def test_automatic_import_persists_bindings_without_deployment_or_writes(self):
        self.app.service.action=lambda *args: self.fail('Import must never deploy')
        self.assertTrue(self.app.wireless.auto_import())
        rows=self.app.get_value('apmng_wserv','wlan_serv')
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[0]['source'],'ap_import')
        self.assertEqual(rows[0]['encryption'],'4')
        self.assertNotIn('key',rows[0]);self.assertNotIn('radius_pwd',rows[0])
        self.assertEqual(len(self.app.profiles),2);self.assertEqual(len(self.app.bindings),2);self.assertFalse(self.calls)
        self.assertTrue(all(b['imported'] and not b['desired'] for b in self.app.bindings.values()))
        self.assertFalse(self.app.wireless.auto_import())
        self.assertFalse(self.app.wireless.reconcile())
        from tplink_ac.web import Application
        restored=Application(self.app.root,self.tmp.name)
        history=restored.get_value('apmng_wserv','wlan_serv')
        self.assertEqual([r['serv_id'] for r in rows],[r['serv_id'] for r in history])
        self.assertTrue(all('历史' in r['source_label'] for r in history))
        self.assertEqual(restored.wireless.observed[self.mac]['rows']['wlan_serv_1']['unknown_future_flag'],'keep')

    def test_renames_replace_rows_and_removed_services_disappear_only_after_read(self):
        self.app.wireless.auto_import();before=self.app.wireless.service_rows()
        self.data['wireless']['wlan_serv'][0]['wlan_serv_1']['ssid']='Renamed'
        self.data['wireless']['wlan_serv'].pop()
        self.app.wireless.read_ap(self.mac)
        rows=self.app.wireless.service_rows()
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['ssid'],'Renamed')
        self.assertEqual(rows[0]['serv_id'],before[0]['serv_id']);self.assertFalse(self.calls)

    def test_failed_read_keeps_history_and_throttles_retries(self):
        self.app.wireless.auto_import();old=copy.deepcopy(self.app.wireless.observed)
        attempts=[]
        def broken(mac,*args):
            attempts.append(mac);raise ValueError('unsupported firmware')
        self.app.wireless.exchange=broken
        self.app.service.snapshot=lambda:{'aps':[{'ip':'192.0.2.155','mac':self.mac,'state':'run','last_seen_seconds':1,'session_epoch':'new-session','radio_ids':[1,2]}]}
        self.assertTrue(self.app.wireless.auto_import());self.assertFalse(self.app.wireless.auto_import())
        self.assertEqual(attempts,[self.mac]);self.assertEqual(self.app.wireless.observed,old)
        self.assertTrue(all('历史' in r['source_label'] for r in self.app.wireless.service_rows()))

    def test_owned_slot_not_duplicated_and_import_never_uses_old_mutation_path(self):
        self.app.profiles['1']={'serv_id':'1','ssid':'Other','key':'password','encryption':'1'}
        self.app.bindings[('1','258')]={'mac':self.mac,'radio':2,'wlan':1,'active':True}
        self.app.wireless.read_ap(self.mac)
        rows=self.app.wireless.service_rows();self.assertEqual(len(rows),2)
        imported=next(r for r in rows if r['source']=='ap_import')
        for method in ('delete','set'):
            with self.assertRaisesRegex(ValueError,'原有服务'):
                self.app.ds({'method':method,'apmng_wserv':{'table':'wlan_serv','filter':[{'serv_id':['1',imported['serv_id']]}],'para':{'enable':'off'}}})
        self.assertIn('1',self.app.profiles);self.assertFalse(self.calls)

    def test_same_config_on_another_ap_merges_and_ip_change_preserves_identity(self):
        self.app.wireless.read_ap(self.mac)
        first=self.app.wireless.service_rows()[0]['serv_id']
        record=copy.deepcopy(self.app.wireless.observed[self.mac])
        self.app.wireless.observed['02:00:00:00:00:02']=record
        self.app.wireless.imported.sync({'mac':'02:00:00:00:00:02','entry_id':'2','session_epoch':'second'},record['rows'])
        rows=self.app.wireless.service_rows()
        self.assertEqual(len(rows),2);self.assertEqual(len(self.app.bindings),4)
        self.app.wireless.observed[self.mac]['ip']='192.0.2.199'
        self.assertEqual(self.app.wireless.service_rows()[0]['serv_id'],first)

if __name__=='__main__':unittest.main()
