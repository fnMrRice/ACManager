"""Windows launcher: original firmware web UI + a loopback-only Python backend."""
import argparse
from pathlib import Path
import sys
import webbrowser
import threading
import traceback

SOURCE_ROOT = Path(__file__).resolve().parents[1]
if not getattr(sys,'frozen',False): sys.path.insert(0,str(SOURCE_ROOT/'src'))
from tplink_ac.web import Application,create_server

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--headless',action='store_true')
    parser.add_argument('--data-dir')
    args = parser.parse_args()
    frozen = getattr(sys,'frozen',False)
    root = Path(sys._MEIPASS)/'web' if frozen else SOURCE_ROOT/'web'
    base = Path(sys.executable).parent if frozen else SOURCE_ROOT
    data = Path(args.data_dir) if args.data_dir else base/'data'
    app = Application(root,data)
    server = create_server(app,args.port)
    url = 'http://127.0.0.1:%d/#/systemState/homeApStatus' % server.server_port
    if not args.headless: threading.Timer(0.5,lambda:webbrowser.open(url)).start()
    if sys.stdout: print(url,flush=True)
    app.start_maintenance()
    try: server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt: pass
    finally: app.stop_maintenance(); app.service.stop(); server.server_close()

if __name__=='__main__':
    try: main()
    except Exception:
        if sys.stderr: traceback.print_exc()
        else:
            import tkinter as tk
            from tkinter import messagebox
            window=tk.Tk();window.withdraw()
            messagebox.showerror('Windows AC 启动失败',traceback.format_exc()[-2500:])
            window.destroy()
