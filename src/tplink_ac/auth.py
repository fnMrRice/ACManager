"""Bounded, expiring web sessions, independent of the router's SSH account."""
import hashlib
import hmac
from http.cookies import SimpleCookie, CookieError
import secrets
import threading
import time


class WebAuth:
    def __init__(self, username, password, clock=time.monotonic):
        if not isinstance(username, str) or not 1 <= len(username) <= 64:
            raise ValueError('管理用户名应为 1..64 个字符')
        if not isinstance(password, str) or not 12 <= len(password) <= 256:
            raise ValueError('管理密码应为 12..256 个字符')
        self.username = username.encode('utf8')
        self.salt = secrets.token_bytes(16)
        self.digest = self._hash(password)
        self.clock, self.lock = clock, threading.RLock()
        self.sessions, self.attempts = {}, {}

    def _hash(self, password):
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf8'), self.salt, 210000)

    def login(self, username, password, peer):
        with self.lock:
            now = self.clock()
            self.attempts = {k:v for k,v in self.attempts.items() if now-v[0] < 60}
            since, count = self.attempts.get(peer, (now, 0))
            if count >= 5 or sum(v[1] for v in self.attempts.values()) >= 30:
                raise ValueError('尝试次数过多，请一分钟后再试')
            self.attempts[peer] = (since, count+1)
            if not isinstance(username,str) or not isinstance(password,str) or len(password)>256:
                return None
            valid_password = hmac.compare_digest(self._hash(password), self.digest)
            if not hmac.compare_digest(username.encode('utf8'), self.username) or not valid_password:
                return None
            self.attempts.pop(peer, None)
            self.sessions = {k:v for k,v in self.sessions.items() if now-v[2] < 1800 and now-v[1] < 43200}
            if len(self.sessions) >= 32:
                del self.sessions[min(self.sessions, key=lambda k:self.sessions[k][2])]
            sid, token = secrets.token_hex(32), secrets.token_hex(24)
            self.sessions[sid] = (token, now, now)
            return sid

    @staticmethod
    def cookie_id(header):
        try:
            cookie = SimpleCookie(); cookie.load(header or '')
            return cookie['ac_session'].value if 'ac_session' in cookie else ''
        except CookieError:
            return ''

    def token(self, header):
        with self.lock:
            sid, now = self.cookie_id(header), self.clock()
            session = self.sessions.get(sid)
            if not session: return None
            token, created, seen = session
            if now-seen >= 1800 or now-created >= 43200:
                del self.sessions[sid]
                return None
            self.sessions[sid] = (token, created, now)
            return token

    def logout(self, header):
        with self.lock: self.sessions.pop(self.cookie_id(header), None)
