"""Loopback integration only: never broadcasts or contacts a real AP."""
import sys
import json
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'.tools/python'),str(ROOT/'tests')]
from test_core import BOARD,RADIO,SID
from tplink_ac.protocol import encode,decode,tlv,vendor,WLAN_RESPONSE
from tplink_ac.service import Service,DEFAULTS
from tplink_ac.dtls import Library,Credentials,Session
from tplink_ac.certificates import generate
from tplink_ac.web import Application,create_server

class NetworkTests(unittest.TestCase):
    def test_dtls_ap_lifecycle_over_udp(self):
        self.exercise_dtls_lifecycle(False)

    def test_tplink_inner_dtls_header_over_udp(self):
        self.exercise_dtls_lifecycle(True)

    def exercise_dtls_lifecycle(self,inner_type):
        with tempfile.TemporaryDirectory() as tmp:
            cert=generate(Path(tmp)/'cert')
            ports=[]
            for _ in range(2):
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                    s.bind(('127.0.0.1',0));ports.append(s.getsockname()[1])
            service=Service()
            try:
                service.start(DEFAULTS|cert|{'enabled':True,'ac_ip':'127.0.0.1','listen_ip':'127.0.0.1',
                    'allowed_ips':['127.0.0.1'],'control_port':ports[0],'data_port':ports[1],
                    'dtls_backend':'openssl'})
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                    sock.bind(('127.0.0.1',0));sock.settimeout(2)
                    peer=('127.0.0.1',ports[0])
                    sock.sendto(encode(1,1,BOARD+RADIO+vendor(9,b'')),peer)
                    self.assertEqual(decode(sock.recv(65535)).kind,2)
                    cred=Credentials(Library(),cert['cert'],cert['key'],cert['ca'])
                    client=Session(cred,lambda data:sock.sendto(data,peer),server=False)
                    try:
                        client.poll()
                        deadline=time.monotonic()+5
                        while not client.ready and time.monotonic()<deadline:
                            client.feed(sock.recv(65535))
                        self.assertTrue(client.ready)
                        def send(packet):
                            client.send(b'\x01'+packet[1:] if inner_type else packet)
                        def receive(packet):
                            self.assertEqual(packet[0],1 if inner_type else 0)
                            return decode(b'\0'+packet[1:])
                        def exchange(packet):
                            send(packet)
                            deadline=time.monotonic()+3
                            while time.monotonic()<deadline:
                                result=client.feed(sock.recv(65535))
                                if result: return receive(result[0])
                            self.fail('no reply')
                        self.assertEqual(exchange(encode(3,3,BOARD+SID)).kind,4)
                        self.assertEqual(exchange(encode(5,5)).kind,6)
                        self.assertEqual(exchange(encode(11,11)).kind,12)
                        service.action('127.0.0.1','apply',{'ssid':'Lab','key':'password'})
                        messages=[]
                        while not messages: messages=client.feed(sock.recv(65535))
                        request=receive(messages[0])
                        send(encode(WLAN_RESPONSE,request.sequence,tlv(33,bytes(4))))
                        deadline=time.monotonic()+2
                        while time.monotonic()<deadline:
                            status=service.snapshot()
                            if status['aps'][0]['last_operation']['status']=='acknowledged': break
                            time.sleep(.02)
                        self.assertEqual(status['aps'][0]['last_operation']['status'],'acknowledged')
                        # Data-channel keepalive ties to the authenticated session.
                        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as data:
                            data.settimeout(2)
                            packet=struct.pack('!IHHH',(2<<19)|8,0,0,len(SID)+2)+SID
                            data.sendto(packet,('127.0.0.1',ports[1]))
                            self.assertEqual(data.recv(128),packet)
                    finally: client.close();cred.close()
            finally: service.stop()

    def test_http_authorization_and_original_ui(self):
        with tempfile.TemporaryDirectory() as tmp:
            app=Application(ROOT/'web',tmp)
            server=create_server(app,0)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            base='http://127.0.0.1:'+str(server.server_port)
            try:
                html=urlopen(base+'/').read().decode()
                self.assertIn('web-static',html);self.assertIn(app.token,html)
                self.assertIn('/ap-list.js?v=7',html)
                with urlopen(base+'/ap-list.js?v=7') as response:
                    self.assertIn('window.acEditAp',response.read().decode())
                with urlopen(base+'/navigation.json') as response:
                    self.assertEqual(json.load(response)['homeApStatus'],['系统状态','AP列表'])
                with urlopen(base+'/bridge.js') as response:
                    self.assertNotIn('接管与备注',response.read().decode())
                with self.assertRaises(HTTPError) as caught: urlopen(base+'/api/status')
                self.assertEqual(caught.exception.code,403)
                def post(body,headers=None,path=None):
                    return json.load(urlopen(Request(base+(path or '/stok='+app.token+'/ds'),data=json.dumps(body).encode(),headers={'Content-Type':'application/json'}|(headers or {}))))
                self.assertEqual(post({'method':'get','apmng_status':{'table':'ap_list'}})['error_code'],0)
                result=post({'method':'do','system':{'reboot':{}}})
                self.assertNotEqual(result['error_code'],0)
                with self.assertRaises(HTTPError) as caught:
                    post({},headers={'Origin':'http://untrusted.example'})
                self.assertEqual(caught.exception.code,403)
                with self.assertRaises(HTTPError) as caught:
                    urlopen(Request(base+'/health',headers={'Host':'untrusted.example'}))
                self.assertEqual(caught.exception.code,403)
            finally: server.shutdown();server.server_close();thread.join()

if __name__=='__main__': unittest.main()
