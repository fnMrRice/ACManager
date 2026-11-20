"""Session boundaries, expiry, login throttling and original-UI authentication."""
import sys
import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor
from urllib.error import HTTPError
from http.cookiejar import CookieJar
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'src'), str(ROOT/'.tools/python')]
from tplink_ac.auth import WebAuth
from tplink_ac.web import Application, create_server


class AuthTests(unittest.TestCase):
    def test_luci_form_login_redirect_and_origin_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            app=Application(ROOT/'web',tmp)
            password='saved-pass&=中文+123'
            auth=WebAuth('admin',password)
            server=create_server(app,0,auth=auth)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            base='http://127.0.0.1:'+str(server.server_port)
            jar=CookieJar();browser=build_opener(HTTPCookieProcessor(jar))
            def submit(origin,secret=password):
                headers={'Content-Type':'application/x-www-form-urlencoded'}
                if origin is not None: headers['Origin']=origin
                return browser.open(Request(base+'/login/luci',
                    data=urlencode({'username':'admin','password':secret}).encode(),headers=headers))
            try:
                for origin in (None,'http://other.example','http://127.0.0.1.attacker.example','null'):
                    with self.assertRaises(HTTPError) as err: submit(origin)
                    self.assertEqual(err.exception.code,403);err.exception.close()
                self.assertFalse(auth.sessions)
                with self.assertRaises(HTTPError) as err: submit('http://127.0.0.1','incorrect')
                self.assertEqual(err.exception.code,401)
                page=err.exception.read().decode();err.exception.close()
                self.assertIn('自动登录失败',page);self.assertIn('id="login"',page)
                self.assertNotIn('incorrect',page)
                with submit('http://127.0.0.1') as response:
                    page=response.read().decode()
                    self.assertIn('sessionStorage.setItem("stok"',page)
                    self.assertNotIn('/login',response.url)
                    self.assertNotIn('password',response.url)
                    self.assertNotIn(password,page)
                self.assertEqual(len(list(jar)),1)
                with submit('https://127.0.0.1:8443') as response:
                    self.assertIn('sessionStorage.setItem("stok"',response.read().decode())
            finally: server.shutdown();server.server_close();thread.join()

    def test_expiry_and_throttle(self):
        now = [0]
        auth = WebAuth('admin','test-password-123',lambda:now[0])
        sid = auth.login('admin','test-password-123','peer')
        cookie = 'ac_session='+sid
        self.assertTrue(auth.token(cookie))
        now[0] = 1800
        self.assertIsNone(auth.token(cookie))
        for _ in range(5): self.assertIsNone(auth.login('admin','wrong','peer'))
        with self.assertRaises(ValueError): auth.login('admin','test-password-123','peer')
        now[0] += 61
        self.assertTrue(auth.login('admin','test-password-123','peer'))

    def test_lan_requires_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Application(ROOT/'web',tmp)
            with self.assertRaises(ValueError): create_server(app,0,'192.0.2.1')
            with self.assertRaises(ValueError): create_server(app,0,'0.0.0.0')

    def test_login_original_api_session_isolation_and_logout(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Application(ROOT/'web',tmp)
            auth = WebAuth('admin','test-password-123')
            server = create_server(app,0,auth=auth)
            thread = threading.Thread(target=server.serve_forever,daemon=True); thread.start()
            base = 'http://127.0.0.1:'+str(server.server_port)
            browser = build_opener(HTTPCookieProcessor(CookieJar()))
            def post(path, data, headers=None, opener=browser):
                return opener.open(Request(base+path,data=json.dumps(data).encode(),headers={'Content-Type':'application/json'}|(headers or {})))
            try:
                landing = urlopen(base+'/').read().decode()
                self.assertIn('AC 管理登录',landing)
                self.assertNotIn(app.token,landing)
                with self.assertRaises(HTTPError) as err:
                    post('/api/status',{},opener=build_opener())
                self.assertEqual(err.exception.code,401)
                with self.assertRaises(HTTPError) as err:
                    post('/login',{'username':'admin','password':'test-password-123'}, {'Origin':'http://other.example'})
                self.assertEqual(err.exception.code,403)
                with self.assertRaises(HTTPError): post('/login',{'username':'admin','password':'wrong'})
                response = post('/login',{'username':'admin','password':'test-password-123'})
                self.assertIn('HttpOnly',response.headers['Set-Cookie'])
                self.assertIn('SameSite=Strict',response.headers['Set-Cookie'])
                import re
                html = browser.open(base+'/').read().decode()
                token = re.search(r'setItem\("stok","([a-f0-9]+)',html)[1]
                self.assertNotEqual(token,app.token)
                request = {'method':'get','apmng_status':{'table':'ap_list'}}
                self.assertEqual(json.load(post('/stok='+token+'/ds',request))['error_code'],0)
                with self.assertRaises(HTTPError): post('/stok='+token+'/ds',request,opener=build_opener())
                with self.assertRaises(HTTPError): post('/api/status',{}, {'X-AC-Token':app.token})
                self.assertTrue(json.load(post('/api/logout',{}, {'X-AC-Token':token}))['ok'])
                with self.assertRaises(HTTPError): post('/stok='+token+'/ds',request)
                post('/login',{'username':'admin','password':'test-password-123'}).close()
                html = browser.open(base+'/').read().decode()
                token = re.search(r'setItem\("stok","([a-f0-9]+)',html)[1]
                logout = post('/stok='+token+'/ds',{'method':'do','system':{'logout':'null'}})
                self.assertIn('Max-Age=0',logout.headers['Set-Cookie'])
                self.assertTrue(json.load(logout)['logged_out'])
                with self.assertRaises(HTTPError): post('/stok='+token+'/ds',request)
            finally:
                server.shutdown();server.server_close();thread.join()

if __name__ == '__main__': unittest.main()
