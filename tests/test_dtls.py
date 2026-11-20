import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'.tools/python')]
from tplink_ac.certificates import generate
from tplink_ac.dtls import Library,Credentials,Session,DTLSError

class DTLSTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.files=generate(Path(self.temp.name)/'cert')
        self.lib=Library()

    def pair(self,ca=None,legacy=False):
        f=self.files
        server_cred=Credentials(self.lib,f['cert'],f['key'],f['ca'],legacy=legacy)
        self.addCleanup(server_cred.close)
        client_cred=Credentials(self.lib,f['cert'],f['key'],ca or f['ca'],legacy=legacy)
        if legacy: self.lib.check(self.lib.SSL_CTX_ctrl(client_cred.handle,124,0xfeff,None),'test DTLS 1.0 maximum')
        self.addCleanup(client_cred.close)
        to_client,to_server=[],[]
        server=Session(server_cred,to_client.append)
        client=Session(client_cred,to_server.append,server=False)
        self.addCleanup(server.close);self.addCleanup(client.close)
        return server,client,to_client,to_server

    def test_mutual_auth_and_datagram_boundaries(self):
        server,client,to_client,to_server=self.pair()
        client.poll()
        for _ in range(20):
            while to_server: server.feed(to_server.pop(0))
            while to_client: client.feed(to_client.pop(0))
            if server.ready and client.ready: break
        self.assertTrue(server.ready and client.ready)
        client.send(b'first');client.send(b'second')
        received=[]
        while to_server: received.extend(server.feed(to_server.pop(0)))
        self.assertEqual(received,[b'first',b'second'])
        server.send(b'response')
        received=[]
        while to_client: received.extend(client.feed(to_client.pop(0)))
        self.assertEqual(received,[b'response'])

    def test_wrong_ca_rejected(self):
        other=generate(Path(self.temp.name)/'other')
        server,client,to_client,to_server=self.pair(other['ca'])
        with self.assertRaises(DTLSError):
            client.poll()
            for _ in range(20):
                while to_server: server.feed(to_server.pop(0))
                while to_client: client.feed(to_client.pop(0))

    def test_opt_in_dtls_10_and_modern_context_isolation(self):
        server,client,to_client,to_server=self.pair(legacy=True)
        client.poll()
        for _ in range(20):
            while to_server: server.feed(to_server.pop(0))
            while to_client: client.feed(to_client.pop(0))
            if server.ready and client.ready: break
        self.assertTrue(server.ready and client.ready)
        self.assertEqual(server.negotiated(),{'version':'DTLSv1','cipher':'AES128-SHA'})
        client.send(b'legacy application data')
        self.assertEqual(server.feed(to_server.pop(0)),[b'legacy application data'])
        modern,modern_client,to_client,to_server=self.pair()
        modern_client.poll()
        for _ in range(20):
            while to_server: modern.feed(to_server.pop(0))
            while to_client: modern_client.feed(to_client.pop(0))
            if modern.ready and modern_client.ready: break
        self.assertEqual(modern.negotiated()['version'],'DTLSv1.2')

if __name__=='__main__': unittest.main()
