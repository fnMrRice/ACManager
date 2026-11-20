"""OpenSSL 3.2+ DTLS for Windows, preserving UDP datagram boundaries."""
import ctypes as C
import os
from pathlib import Path
import sys

PREAMBLE = b'\x01\x00\x00\x00'

class DTLSError(RuntimeError):
    pass

class Library:
    def __init__(self):
        if os.name == 'nt':
            roots = [Path(getattr(sys,'_MEIPASS',sys.base_prefix)), Path(sys.base_prefix)/'DLLs']
            root = next((p for p in roots if (p/'libssl-3.dll').is_file()), None)
            if root is None: raise DTLSError('OpenSSL DLLs not found')
            self.crypto = C.CDLL(str(root/'libcrypto-3.dll'))
            self.ssl = C.CDLL(str(root/'libssl-3.dll'))
        else:
            self.crypto, self.ssl = C.CDLL('libcrypto.so.3'), C.CDLL('libssl.so.3')
        P, I, L, S = C.c_void_p, C.c_int, C.c_long, C.c_char_p
        signatures = {
            'DTLS_method': (P,[]), 'SSL_CTX_new': (P,[P]), 'SSL_CTX_free':(None,[P]),
            'SSL_CTX_use_certificate_chain_file':(I,[P,S]),
            'SSL_CTX_use_PrivateKey_file':(I,[P,S,I]), 'SSL_CTX_check_private_key':(I,[P]),
            'SSL_CTX_load_verify_locations':(I,[P,S,S]), 'SSL_CTX_set_verify':(None,[P,I,P]),
            'SSL_CTX_set_security_level':(None,[P,I]), 'SSL_CTX_set_cipher_list':(I,[P,S]),
            'SSL_CTX_ctrl':(L,[P,I,L,P]), 'SSL_new':(P,[P]), 'SSL_free':(None,[P]),
            'SSL_set_bio':(None,[P,P,P]), 'SSL_set_accept_state':(None,[P]),
            'SSL_set_connect_state':(None,[P]), 'SSL_do_handshake':(I,[P]),
            'SSL_get_error':(I,[P,I]), 'SSL_get_verify_result':(L,[P]),
            'SSL_get1_peer_certificate':(P,[P]), 'SSL_ctrl':(L,[P,I,L,P]),
            'SSL_get_version':(S,[P]), 'SSL_get_current_cipher':(P,[P]), 'SSL_CIPHER_get_name':(S,[P]),
            'SSL_set_options':(C.c_uint64,[P,C.c_uint64]),
            'SSL_read':(I,[P,P,I]), 'SSL_write':(I,[P,P,I]),
            'BIO_s_dgram_mem':(P,[]), 'BIO_new':(P,[P]), 'BIO_free':(I,[P]),
            'BIO_write':(I,[P,P,I]), 'BIO_read':(I,[P,P,I]),
            'BIO_ctrl_pending':(C.c_size_t,[P]),
            'ERR_get_error':(C.c_ulong,[]), 'ERR_error_string_n':(None,[C.c_ulong,P,C.c_size_t]),
            'ERR_clear_error':(None,[]), 'X509_free':(None,[P]),
        }
        for name,(ret,args) in signatures.items():
            library = self.crypto if name.startswith(('BIO_','ERR_','X509_')) else self.ssl
            try: fn = getattr(library,name)
            except AttributeError as e: raise DTLSError('OpenSSL 3.2+ required: '+name) from e
            fn.restype,fn.argtypes = ret,args
            setattr(self,name,fn)

    def error(self, message):
        code = self.ERR_get_error()
        buf = C.create_string_buffer(256)
        self.ERR_error_string_n(code,buf,len(buf))
        return DTLSError(message + ': ' + buf.value.decode('utf8','replace'))

    def check(self, result, message):
        if result <= 0: raise self.error(message)
        return result

class Credentials:
    def __init__(self, library, cert, key, ca='', verify=True, legacy=False):
        self.api,self.verify = library,verify
        self.handle = None
        if verify and not ca: raise DTLSError('验证 AP 证书需要选择 CA 文件')
        self.handle = library.check(library.SSL_CTX_new(library.DTLS_method()),'SSL_CTX_new')
        try:
            library.check(library.SSL_CTX_ctrl(self.handle,123,0xfeff if legacy else 0xfefd,None),'DTLS minimum')
            if legacy:
                # Old APs offer DTLS 1.0 and RSA/AES-CBC only. Scope this
                # compatibility policy to this context; never alter host TLS.
                library.SSL_CTX_set_security_level(self.handle,0)
                library.check(library.SSL_CTX_set_cipher_list(self.handle,b'AES128-SHA:AES256-SHA'),'legacy AES ciphers')
            library.check(library.SSL_CTX_use_certificate_chain_file(self.handle,os.fsencode(cert)),'读取证书失败')
            library.check(library.SSL_CTX_use_PrivateKey_file(self.handle,os.fsencode(key),1),'读取私钥失败')
            library.check(library.SSL_CTX_check_private_key(self.handle),'证书与私钥不匹配')
            if ca: library.check(library.SSL_CTX_load_verify_locations(self.handle,os.fsencode(ca),None),'读取 CA 失败')
            library.SSL_CTX_set_verify(self.handle,3 if verify else 0,None)
        except Exception:
            self.close(); raise

    def close(self):
        if self.handle:
            self.api.SSL_CTX_free(self.handle); self.handle = None

class Session:
    def __init__(self, credentials, send, server=True):
        self.api,self.credentials,self.send_datagram = credentials.api,credentials,send
        self.handle,self.ready = None,False
        self.input,self.output = None,None
        a = self.api
        self.handle = a.check(a.SSL_new(credentials.handle),'SSL_new')
        try:
            self.input = a.check(a.BIO_new(a.BIO_s_dgram_mem()),'BIO input')
            self.output = a.check(a.BIO_new(a.BIO_s_dgram_mem()),'BIO output')
        except Exception:
            if self.input: a.BIO_free(self.input)
            a.SSL_free(self.handle); self.handle = None
            raise
        a.SSL_set_bio(self.handle,self.input,self.output)  # SSL owns both BIOs.
        a.SSL_set_options(self.handle,1 << 12)  # SSL_OP_NO_QUERY_MTU
        a.SSL_ctrl(self.handle,17,1200,None)
        (a.SSL_set_accept_state if server else a.SSL_set_connect_state)(self.handle)

    def _drain(self):
        a,buf = self.api,C.create_string_buffer(65535)
        for _ in range(128):
            if not a.BIO_ctrl_pending(self.output): return
            size = a.BIO_read(self.output,buf,len(buf))
            a.check(size,'BIO read')
            self.send_datagram(PREAMBLE+buf.raw[:size])
        raise DTLSError('excessive DTLS output')

    def _result(self, value):
        if value > 0: return True
        error = self.api.SSL_get_error(self.handle,value)
        if error in (2,3): return False  # WANT_READ / WANT_WRITE
        raise self.api.error('DTLS error %d' % error)

    def feed(self, data):
        if not data.startswith(PREAMBLE) or not 17 <= len(data) <= 65507:
            raise DTLSError('invalid DTLS datagram')
        self.api.check(self.api.BIO_write(self.input,data[4:],len(data)-4),'BIO write')
        return self.poll()

    def poll(self):
        a = self.api
        a.ERR_clear_error()
        if a.SSL_ctrl(self.handle,74,0,None) < 0:  # DTLS_CTRL_HANDLE_TIMEOUT
            raise a.error('DTLS retransmission failed')
        if not self.ready:
            if not self._result(a.SSL_do_handshake(self.handle)):
                self._drain(); return []
            if self.credentials.verify:
                cert = a.SSL_get1_peer_certificate(self.handle)
                if not cert: raise DTLSError('AP 未提供证书')
                a.X509_free(cert)
                if a.SSL_get_verify_result(self.handle): raise DTLSError('AP 证书验证失败')
            self.ready = True
        self._drain()
        result,buf = [],C.create_string_buffer(65535)
        for _ in range(64):
            a.ERR_clear_error()
            size = a.SSL_read(self.handle,buf,len(buf))
            if not self._result(size): break
            result.append(buf.raw[:size])
        self._drain()
        return result

    def send(self, data):
        if not self.ready: raise DTLSError('DTLS handshake incomplete')
        self.api.ERR_clear_error()
        size = self.api.SSL_write(self.handle,data,len(data))
        if not self._result(size) or size != len(data): raise DTLSError('DTLS write incomplete')
        self._drain()

    def negotiated(self):
        if not self.ready: return {}
        return {'version':self.api.SSL_get_version(self.handle).decode('ascii'),
                'cipher':self.api.SSL_CIPHER_get_name(self.api.SSL_get_current_cipher(self.handle)).decode('ascii')}

    def close(self):
        if self.handle:
            self.api.SSL_free(self.handle); self.handle = None
