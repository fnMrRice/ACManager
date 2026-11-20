"""Headless Linux/OpenWrt host for the shared controller and original web UI."""
import argparse
import json
from pathlib import Path
import signal
import subprocess
import threading
from .web import Application,create_server
from .auth import WebAuth

def router_settings():
    """Read secrets locally, never from process arguments or log output."""
    def get(key):
        return subprocess.check_output(['uci','-q','get','tplink_ac.main.'+key],text=True).rstrip('\n')
    port = int(get('port'))
    if not 1 <= port <= 65535: raise ValueError('网页端口无效')
    auth = WebAuth(get('username'),get('password'))
    network = json.loads(subprocess.check_output(['ubus','call','network.interface.lan','status'],text=True))
    addresses = network.get('ipv4-address',[])
    if not addresses: raise ValueError('LAN 没有 IPv4 地址，网页服务未启动')
    return addresses[0]['address'],port,auth

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--data',type=Path,required=True)
    p.add_argument('--port',type=int,default=8765)
    p.add_argument('--start',action='store_true',help='Start UDP using saved settings')
    p.add_argument('--uci',action='store_true',help='Use OpenWrt LAN address and tplink_ac web settings')
    a=p.parse_args()
    app=Application(a.root,a.data)
    listen,port,auth = router_settings() if a.uci else ('127.0.0.1',a.port,None)
    server=create_server(app,port,listen,auth)
    def stop(*args): threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:
        if a.start: app.service.start(app.config)
        app.start_maintenance()
        print(f'AC lab HTTP {listen}:{server.server_port}; hardware validation pending',flush=True)
        server.serve_forever(poll_interval=.2)
    finally:
        app.stop_maintenance();app.service.stop();server.server_close()

if __name__=='__main__': main()
