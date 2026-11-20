"""Linux GnuTLS DTLS transport with the CAPWAP four-byte preamble.

No vendor private keys are bundled. The caller supplies credentials and trust.
Callbacks preserve datagram boundaries; a bounded queue prevents memory growth.
"""
import ctypes as C
import errno
import os
import socket
import struct
from collections import deque

PREAMBLE = b'\x01\x00\x00\x00'
IO = C.CFUNCTYPE(C.c_ssize_t, C.c_void_p, C.c_void_p, C.c_size_t)
TIMEOUT = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_uint)

class Datum(C.Structure):
    _fields_ = [('data',C.c_void_p),('size',C.c_uint)]

class Prestate(C.Structure):
    _fields_ = [('record_seq',C.c_uint),('hsk_read_seq',C.c_uint),('hsk_write_seq',C.c_uint)]

class DTLSError(RuntimeError):
    pass

class Library:
    def __init__(self):
        self.lib = C.CDLL('libgnutls.so.30')
        signatures = {
            'global_init': (C.c_int, []), 'init': (C.c_int, [C.POINTER(C.c_void_p), C.c_uint]),
            'deinit': (None, [C.c_void_p]), 'strerror': (C.c_char_p, [C.c_int]),
            'certificate_allocate_credentials': (C.c_int, [C.POINTER(C.c_void_p)]),
            'certificate_free_credentials': (None, [C.c_void_p]),
            'certificate_set_x509_key_file': (C.c_int, [C.c_void_p,C.c_char_p,C.c_char_p,C.c_int]),
            'certificate_set_x509_trust_file': (C.c_int, [C.c_void_p,C.c_char_p,C.c_int]),
            'certificate_server_set_request': (None, [C.c_void_p,C.c_int]),
            'certificate_verify_peers2': (C.c_int, [C.c_void_p,C.POINTER(C.c_uint)]),
            'credentials_set': (C.c_int, [C.c_void_p,C.c_uint,C.c_void_p]),
            'priority_set_direct': (C.c_int, [C.c_void_p,C.c_char_p,C.c_void_p]),
            'transport_set_push_function': (None, [C.c_void_p,IO]),
            'transport_set_pull_function': (None, [C.c_void_p,IO]),
            'transport_set_pull_timeout_function': (None, [C.c_void_p,TIMEOUT]),
            'transport_set_errno': (None, [C.c_void_p,C.c_int]),
            'dtls_set_mtu': (None, [C.c_void_p,C.c_uint]),
            'dtls_set_timeouts': (None, [C.c_void_p,C.c_uint,C.c_uint]),
            'dtls_cookie_verify': (C.c_int,[C.POINTER(Datum),C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.POINTER(Prestate)]),
            'dtls_cookie_send': (C.c_int,[C.POINTER(Datum),C.c_void_p,C.c_size_t,C.POINTER(Prestate),C.c_void_p,IO]),
            'dtls_prestate_set': (None,[C.c_void_p,C.POINTER(Prestate)]),
            'handshake': (C.c_int, [C.c_void_p]),
            'record_recv': (C.c_ssize_t, [C.c_void_p,C.c_void_p,C.c_size_t]),
            'record_send': (C.c_ssize_t, [C.c_void_p,C.c_void_p,C.c_size_t]),
            'protocol_get_version': (C.c_int, [C.c_void_p]),
            'protocol_get_name': (C.c_char_p, [C.c_int]),
            'cipher_get': (C.c_int, [C.c_void_p]),
            'cipher_get_name': (C.c_char_p, [C.c_int]),
        }
        for name, (ret, args) in signatures.items():
            fn = getattr(self.lib, 'gnutls_' + name)
            fn.restype, fn.argtypes = ret, args
            setattr(self, name, fn)
        self.check(self.global_init())

    def check(self, code):
        if code < 0:
            raise DTLSError(self.strerror(code).decode('utf-8', 'replace'))
        return code

class CookieGate:
    """Stateless address validation before allocating a DTLS session."""
    def __init__(self, library):
        self.api = library
        self.secret = C.create_string_buffer(os.urandom(16))
        self.key = Datum(C.cast(self.secret,C.c_void_p),16)

    def receive(self, peer, packet, send):
        if not packet.startswith(PREAMBLE) or len(packet)<64 or len(packet)>1500: return None
        data=packet[4:]
        if data[0]!=22 or data[3:5]!=b'\0\0' or data[13]!=1: return None
        identity=socket.inet_aton(peer[0])+struct.pack('!H',peer[1])
        state=Prestate()
        result=self.api.dtls_cookie_verify(C.byref(self.key),identity,len(identity),data,len(data),C.byref(state))
        if result>=0: return state
        def push(_,pointer,size):
            try: send(PREAMBLE+C.string_at(pointer,size));return size
            except OSError: return -1
        callback=IO(push)
        self.api.check(self.api.dtls_cookie_send(C.byref(self.key),identity,len(identity),C.byref(state),None,callback))
        return None

class Credentials:
    def __init__(self, library, cert, key, ca='', verify=True, legacy=False):
        self.api, self.handle, self.verify = library, C.c_void_p(), verify
        self.legacy = legacy
        if verify and not ca:
            raise DTLSError('peer verification requires a CA file')
        library.check(library.certificate_allocate_credentials(C.byref(self.handle)))
        try:
            library.check(library.certificate_set_x509_key_file(self.handle, cert.encode(), key.encode(), 1))
            if ca:
                if library.check(library.certificate_set_x509_trust_file(self.handle, ca.encode(), 1)) == 0:
                    raise DTLSError('CA file contains no certificates')
        except Exception:
            self.close(); raise

    def close(self):
        if self.handle:
            self.api.certificate_free_credentials(self.handle)
            self.handle = C.c_void_p()

class Session:
    def __init__(self, credentials, send, server=True,
                 priority=None, prestate=None):
        self.api, self.credentials, self.send_datagram = credentials.api, credentials, send
        self.handle, self.queue, self.ready = C.c_void_p(), deque(), False
        self.api.check(self.api.init(C.byref(self.handle), (1 if server else 2) | 4 | 8))
        try:
            if priority is None:
                priority = ('NORMAL:-VERS-ALL:+VERS-DTLS1.2:+VERS-DTLS1.0:-KX-ALL:+RSA:-CIPHER-ALL:+AES-128-CBC:+AES-256-CBC'
                            if credentials.legacy else 'NORMAL:-VERS-ALL:+VERS-DTLS1.2')
            self.api.check(self.api.priority_set_direct(self.handle, priority.encode(), None))
            self.api.check(self.api.credentials_set(self.handle, 1, credentials.handle))
            if prestate is not None: self.api.dtls_prestate_set(self.handle,C.byref(prestate))
            if server and credentials.verify:
                self.api.certificate_server_set_request(self.handle, 2)
            self.push_cb, self.pull_cb, self.timeout_cb = IO(self._push), IO(self._pull), TIMEOUT(self._timeout)
            self.api.transport_set_push_function(self.handle, self.push_cb)
            self.api.transport_set_pull_function(self.handle, self.pull_cb)
            self.api.transport_set_pull_timeout_function(self.handle, self.timeout_cb)
            self.api.dtls_set_mtu(self.handle, 1200)
            self.api.dtls_set_timeouts(self.handle, 1000, 15000)
        except Exception:
            self.close(); raise

    def _push(self, _, data, size):
        try:
            self.send_datagram(PREAMBLE + C.string_at(data, size))
            return size
        except Exception:
            self.api.transport_set_errno(self.handle, errno.EIO)
            return -1

    def _pull(self, _, data, size):
        if not self.queue:
            self.api.transport_set_errno(self.handle, errno.EAGAIN)
            return -1
        packet = self.queue.popleft()
        if len(packet) > size:
            self.api.transport_set_errno(self.handle, errno.EMSGSIZE)
            return -1
        C.memmove(data, packet, len(packet))
        return len(packet)

    def _timeout(self, _, milliseconds):
        return int(bool(self.queue))

    def feed(self, packet):
        if not packet.startswith(PREAMBLE) or not 17 <= len(packet) <= 65507:
            raise DTLSError('invalid CAPWAP DTLS datagram')
        if len(self.queue) >= 64:
            raise DTLSError('DTLS receive queue full')
        self.queue.append(packet[4:])
        return self.poll()

    def poll(self):
        if not self.ready:
            result = self.api.handshake(self.handle)
            if result in (-28,-52): return []
            self.api.check(result)
            if self.credentials.verify:
                status = C.c_uint()
                self.api.check(self.api.certificate_verify_peers2(self.handle, C.byref(status)))
                if status.value:
                    raise DTLSError('peer certificate verification failed: %d' % status.value)
            self.ready = True
        result, buf = [], C.create_string_buffer(65535)
        for _ in range(64):
            size = self.api.record_recv(self.handle, buf, len(buf))
            if size in (-28,-52): break
            self.api.check(size)
            if size == 0: raise DTLSError('peer closed DTLS')
            result.append(buf.raw[:size])
        return result

    def send(self, data):
        if not self.ready: raise DTLSError('DTLS handshake incomplete')
        result = self.api.record_send(self.handle, data, len(data))
        self.api.check(result)
        if result != len(data): raise DTLSError('incomplete DTLS write')

    def close(self):
        if self.handle:
            self.api.deinit(self.handle)
            self.handle = C.c_void_p()

    def negotiated(self):
        if not self.ready: return {}
        a = self.api
        return {'version':a.protocol_get_name(a.protocol_get_version(self.handle)).decode('ascii'),
                'cipher':a.cipher_get_name(a.cipher_get(self.handle)).decode('ascii')}
