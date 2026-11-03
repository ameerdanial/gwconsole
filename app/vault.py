"""Encrypt secrets (Cloudflare tokens, Telegram bot token, Discord webhook) at rest.

Uses Fernet (AES-128-CBC + HMAC-SHA256) with a key kept outside the database in
/etc/gwconsole/secret.key (root:gwconsole 0640), so a copied gwconsole.db alone
does not reveal any secret. install.sh creates the key.
"""
from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, key_file: str, create: bool = False):
        self.key_file = key_file
        if not os.path.exists(key_file):
            if not create:
                raise VaultError(f"secret key {key_file} is missing; re-run install.sh to create it")
            old = os.umask(0o077)
            try:
                os.makedirs(os.path.dirname(key_file) or ".", exist_ok=True)
                with open(key_file, "wb") as f:
                    f.write(Fernet.generate_key())
            except OSError as e:
                raise VaultError(f"secret key {key_file} is missing and cannot be created ({e}); "
                                 "re-run install.sh as root") from e
            finally:
                os.umask(old)
        with open(key_file, "rb") as f:
            self._f = Fernet(f.read().strip())

    def encrypt(self, plain: str) -> str:
        if not plain:
            return ""
        return self._f.encrypt(plain.encode()).decode()

    def decrypt(self, token: str) -> str:
        if not token:
            return ""
        try:
            return self._f.decrypt(token.encode()).decode()
        except InvalidToken as e:
            raise VaultError("cannot decrypt a stored secret: secret.key does not match this database") from e
