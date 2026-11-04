"""Two-step sign-in (v1.5): time-based one-time codes (RFC 6238, the codes authenticator apps show),
recovery codes and the QR code for setting it up.

Standard library only for the codes themselves (HMAC-SHA1, 6 digits, 30-second steps, ±1 step for clock
drift). The secret is stored encrypted with the dashboard's vault; recovery codes are stored as scrypt
hashes and each one works once. QR codes are drawn as SVG by `segno` (pure Python).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP, DIGITS, WINDOW = 30, 6, 1
ISSUER = "GW//CONSOLE"
RC_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"        # no 0/O, 1/I


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret: str, step: int) -> str:
    mac = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    n = (struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(n).zfill(DIGITS)


def now_step(t: float | None = None) -> int:
    return int((time.time() if t is None else t) // STEP)


def verify(secret: str, code: str, last_step: int = 0, t: float | None = None) -> int | None:
    """The time step the code belongs to (within ±1 step), or None. A step at or before `last_step`
    is refused, so the same code can't be used twice."""
    c = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(c) != DIGITS or not secret:
        return None
    cur = now_step(t)
    for s in range(cur - WINDOW, cur + WINDOW + 1):
        if s > last_step and hmac.compare_digest(code_at(secret, s), c):
            return s
    return None


def uri(secret: str, user: str) -> str:
    label = quote(f"{ISSUER}:{user}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits={DIGITS}&period={STEP}"


def qr_svg(text: str) -> str:
    """The setup QR code as inline SVG (dark modules on white, so every phone camera reads it)."""
    import io

    import segno
    buf = io.BytesIO()
    segno.make(text, error="m").save(buf, kind="svg", scale=5, border=2, dark="#0b0d16", light="#ffffff",
                                     xmldecl=False, svgns=True)
    return buf.getvalue().decode()


def pretty(secret: str) -> str:
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


# ---------------------------------------------------------------- recovery codes
def new_recovery_codes(n: int = 10) -> list[str]:
    out = []
    for _ in range(n):
        raw = "".join(secrets.choice(RC_ALPHABET) for _ in range(10))
        out.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:]}")
    return out


def _norm_rc(code: str) -> str:
    return "".join(ch for ch in str(code or "").upper() if ch.isalnum())


def hash_recovery(code: str) -> dict:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(_norm_rc(code).encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return {"s": base64.b64encode(salt).decode(), "h": base64.b64encode(dk).decode(), "used": 0}


def match_recovery(code: str, stored: list[dict]) -> int | None:
    """Index of the unused recovery code that matches, or None."""
    c = _norm_rc(code)
    if len(c) != 10:
        return None
    for i, r in enumerate(stored):
        if r.get("used"):
            continue
        dk = hashlib.scrypt(c.encode(), salt=base64.b64decode(r["s"]), n=2 ** 14, r=8, p=1, dklen=32)
        if hmac.compare_digest(dk, base64.b64decode(r["h"])):
            return i
    return None
