"""Password hashing (stdlib scrypt) and in-memory sessions."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

N, R, P = 2 ** 15, 8, 1


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=N, r=R, p=P, maxmem=64 * 1024 * 1024, dklen=32)
    b = lambda x: base64.b64encode(x).decode()
    return f"scrypt${N}${R}${P}${b(salt)}${b(dk)}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                              maxmem=64 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except Exception:
        return False


class Sessions:
    def __init__(self, hours: int):
        self.ttl = hours * 3600
        self._s: dict[str, tuple[str, float]] = {}
        self._fails: dict[str, list[float]] = {}

    def create(self, user: str) -> str:
        tok = secrets.token_urlsafe(32)
        self._s[tok] = (user, time.time() + self.ttl)
        return tok

    def get(self, tok: str | None) -> str | None:
        if not tok:
            return None
        v = self._s.get(tok)
        if not v:
            return None
        user, exp = v
        if exp < time.time():
            self._s.pop(tok, None)
            return None
        return user

    def drop(self, tok: str | None):
        if tok:
            self._s.pop(tok, None)

    # simple brute-force guard: 5 failures / 5 min per IP
    def locked(self, ip: str) -> bool:
        now = time.time()
        f = [t for t in self._fails.get(ip, []) if now - t < 300]
        self._fails[ip] = f
        return len(f) >= 5

    def fail(self, ip: str):
        self._fails.setdefault(ip, []).append(time.time())
