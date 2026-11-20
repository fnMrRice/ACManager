"""Exercise the packaged EXE with a loopback DTLS AP, never real LAN devices."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import Request,urlopen
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'.tools/python'),str(ROOT/'tests')]
from test_core import BOARD,RADIO,SID
from tplink_ac.protocol import *
from tplink_ac.dtls import Library,Credentials,Session

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--hold',type=int,default=0)
    parser.add_argument('--source',action='store_true')
    args=parser.parse_args()
    port=8767;base=f'http://127.0.0.1:{port}'
    with tempfile.TemporaryDirectory(prefix='packaged-test-',dir=ROOT/'build') as tmp:
        command=[sys.executable,str(ROOT/'windows/main.py')] if args.source else [str(ROOT/'dist/TplinkAC/TplinkAC.exe')]
        process=subprocess.Popen(command+['--headless','--port',str(port),'--data-dir',tmp],creationflags=subprocess.CREATE_NO_WINDOW,
                                 env=os.environ|{'PYTHONPATH':str(ROOT/'.tools/python')})
        token=None;session=None;cred=None;sock=None
        try:
            for _ in range(80):
                if process.poll() is not None: raise RuntimeError('EXE exited on startup')
                try:
                    html=urlopen(base+'/',timeout=1).read().decode()
                    token=re.search(r'sessionStorage.setItem\("stok","([a-f0-9]+)"',html).group(1);break
                except OSError: time.sleep(.1)
            if not token: raise RuntimeError('startup timed out')
            def post(path,body=None):
                return json.load(urlopen(Request(base+path,data=json.dumps(body or {}).encode(),headers={'X-AC-Token':token,'Content-Type':'application/json'}),timeout=5))
            def ds(body):
                result=post('/stok='+token+'/ds',body)
                if result['error_code']: raise RuntimeError(result)
                return result
            cert=post('/api/certificates')
            cfg=post('/api/config')|cert|{'enabled':True,'ac_ip':'127.0.0.1','listen_ip':'127.0.0.1','allowed_ips':['127.0.0.1'],'control_port':15246,'data_port':15247}
            post('/api/save',cfg);post('/api/start')
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));sock.settimeout(3)
            peer=('127.0.0.1',15246)
            sock.sendto(encode(1,1,BOARD+RADIO+vendor(9,b'')),peer)
            assert decode(sock.recv(65535)).kind==2
            cred=Credentials(Library(),cert['cert'],cert['key'],cert['ca'])
            session=Session(cred,lambda b:sock.sendto(b,peer),server=False);session.poll()
            while not session.ready: session.feed(sock.recv(65535))
            def receive():
                while True:
                    result=session.feed(sock.recv(65535))
                    if result: return decode(result[0])
            for kind,body in ((3,BOARD+SID),(5,b''),(11,b'')):
                session.send(encode(kind,kind,body));assert receive().kind==kind+1
            ds({'method':'add','apmng_wserv':{'table':'wlan_serv','para':{'ssid':'SIMULATOR-LAB','key':'lab-only-password','auth':'2','cipher':'2','encryption':'1','enable':'on','ssidbrd':'1','auto_bind':'off'}}})
            radios=ds({'method':'get','apmng_wserv':{'table':'radio_bind_list','filter':[{'serv_id':'1'}]}})
            rid=next(iter(radios['apmng_wserv']['radio_bind_list'][0].values()))['radio_id']
            ds({'method':'set','apmng_wserv':{'table':'radio_bind_list','filter':[{'serv_id':'1'}],'para':{'radio_id':[rid],'vlan_id':['0'],'bind_status':'1'}}})
            request=receive();assert request.kind==WLAN_REQUEST
            session.send(encode(WLAN_RESPONSE,request.sequence,tlv(33,bytes(4))))
            for _ in range(30):
                status=post('/api/status')
                if status['aps'][0]['last_operation']['status']=='acknowledged': break
                time.sleep(.02)
            assert status['aps'][0]['last_operation']['status']=='acknowledged'
            ds({'method':'set','apmng_status':{'table':'ap_list','filter':[{'entry_id':'1'}],'para':{'led_status':'1'}}})
            request=receive();assert request.kind==7 and request.private(57)==[b'\0\0\0\x01']
            session.send(encode(8,request.sequence,tlv(33,bytes(4))))
            print(('SOURCE' if args.source else 'PACKAGED EXE')+' PASS: certificate creation, DTLS, AP lifecycle, original /ds profile bind and LED. UI: '+base,flush=True)
            until=time.monotonic()+args.hold
            while time.monotonic()<until:
                session.send(encode(13,50))
                while True:
                    message=receive()
                    if message.kind==14: break
                    if message.kind not in (7,WLAN_REQUEST): raise RuntimeError('unexpected AC command')
                    session.send(encode(message.kind+1,message.sequence,tlv(33,bytes(4))))
                time.sleep(1)
            post('/api/stop');post('/api/shutdown')
            process.wait(timeout=8)
            if process.returncode: raise RuntimeError('nonzero exit')
        finally:
            if session: session.close()
            if cred: cred.close()
            if sock: sock.close()
            if process.poll() is None: process.terminate();process.wait(timeout=5)

if __name__=='__main__': main()
