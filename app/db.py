"""SQLite storage for users (with preferences), sessions, settings, Cloudflare accounts, nodes, alerts and monitoring.

One file at /var/lib/gwconsole/gwconsole.db (WAL mode). The schema is versioned with
PRAGMA user_version; MIGRATIONS[i] upgrades version i -> i+1 and runs exactly once.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager

MIGRATIONS = [
    # 0 -> 1 : v1.2.0
    """
    CREATE TABLE users (
        id            INTEGER PRIMARY KEY,
        username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
        pw_hash       TEXT NOT NULL,
        role          TEXT NOT NULL CHECK (role IN ('viewer','operator','superadmin')),
        disabled      INTEGER NOT NULL DEFAULT 0,
        must_change   INTEGER NOT NULL DEFAULT 0,
        created_at    INTEGER NOT NULL,
        last_login    INTEGER,
        pw_changed_at INTEGER
    );
    CREATE TABLE sessions (
        token_hash TEXT PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        last_seen  INTEGER NOT NULL,
        ip         TEXT,
        user_agent TEXT
    );
    CREATE TABLE settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    CREATE TABLE cf_accounts (
        id         INTEGER PRIMARY KEY,
        name       TEXT NOT NULL UNIQUE,
        account_id TEXT NOT NULL,
        token_enc  TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE nodes (
        id         INTEGER PRIMARY KEY,
        name       TEXT NOT NULL UNIQUE,
        kind       TEXT NOT NULL CHECK (kind IN ('haproxy','cloudflared')),
        data       TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE alerts (
        id          INTEGER PRIMARY KEY,
        key         TEXT NOT NULL,
        kind        TEXT NOT NULL,
        severity    TEXT NOT NULL,
        node        TEXT,
        target      TEXT NOT NULL,
        message     TEXT NOT NULL,
        first_seen  INTEGER NOT NULL,
        last_seen   INTEGER NOT NULL,
        resolved_at INTEGER,
        misses      INTEGER NOT NULL DEFAULT 0,
        flaps       INTEGER NOT NULL DEFAULT 0,
        acked_by    TEXT,
        acked_at    INTEGER
    );
    CREATE INDEX alerts_open  ON alerts (resolved_at, key);
    CREATE INDEX alerts_first ON alerts (first_seen);
    CREATE TABLE mutes (
        id         INTEGER PRIMARY KEY,
        match      TEXT NOT NULL,
        until      INTEGER NOT NULL,
        reason     TEXT,
        created_by TEXT,
        created_at INTEGER NOT NULL
    );
    """,
    # 1 -> 2 : v1.4.0 — "server" node type, monitoring, traffic, update history
    """
    CREATE TABLE nodes_v2 (
        id         INTEGER PRIMARY KEY,
        name       TEXT NOT NULL UNIQUE,
        kind       TEXT NOT NULL CHECK (kind IN ('haproxy','cloudflared','server')),
        data       TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    INSERT INTO nodes_v2 (id, name, kind, data, created_at, updated_at)
        SELECT id, name, kind, data, created_at, updated_at FROM nodes;
    DROP TABLE nodes;
    ALTER TABLE nodes_v2 RENAME TO nodes;
    CREATE TABLE checks (
        host       TEXT PRIMARY KEY,
        kind       TEXT NOT NULL DEFAULT 'http',
        source     TEXT NOT NULL DEFAULT 'auto',
        internal   TEXT NOT NULL DEFAULT '',
        route      TEXT NOT NULL DEFAULT '{}',
        opts       TEXT NOT NULL DEFAULT '{}',
        excluded   INTEGER NOT NULL DEFAULT 0,
        state      TEXT NOT NULL DEFAULT '{}',
        seen_at    INTEGER,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE health (
        node TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        at   INTEGER NOT NULL
    );
    CREATE TABLE services (
        node       TEXT NOT NULL,
        unit       TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (node, unit)
    );
    CREATE TABLE samples (
        series TEXT NOT NULL,
        ts     INTEGER NOT NULL,
        value  REAL NOT NULL,
        PRIMARY KEY (series, ts)
    ) WITHOUT ROWID;
    CREATE TABLE samples_15m (
        series TEXT NOT NULL,
        ts     INTEGER NOT NULL,
        value  REAL NOT NULL,
        n      INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (series, ts)
    ) WITHOUT ROWID;
    CREATE TABLE traffic_daily (
        day      TEXT NOT NULL,
        source   TEXT NOT NULL,
        name     TEXT NOT NULL,
        requests INTEGER NOT NULL DEFAULT 0,
        bytes    INTEGER NOT NULL DEFAULT 0,
        visitors INTEGER NOT NULL DEFAULT 0,
        cached   INTEGER NOT NULL DEFAULT 0,
        threats  INTEGER NOT NULL DEFAULT 0,
        s4xx     INTEGER NOT NULL DEFAULT 0,
        s5xx     INTEGER NOT NULL DEFAULT 0,
        extra    TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY (day, source, name)
    ) WITHOUT ROWID;
    CREATE TABLE update_history (
        id      INTEGER PRIMARY KEY,
        at      INTEGER NOT NULL,
        kind    TEXT NOT NULL,
        from_v  TEXT,
        to_v    TEXT,
        by      TEXT,
        result  TEXT NOT NULL,
        seconds INTEGER
    );
    """,
    # 2 -> 3 : v1.4.1 — per-user preferences, idle sign-out
    """
    ALTER TABLE users ADD COLUMN prefs TEXT NOT NULL DEFAULT '{}';
    ALTER TABLE sessions ADD COLUMN last_active INTEGER;
    UPDATE sessions SET last_active = last_seen;
    """,
]


class DB:
    def __init__(self, path: str):
        self.path = path
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        new = not os.path.exists(path)
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        self.conn.row_factory = sqlite3.Row
        if new:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        self.lock = threading.RLock()
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.migrate()

    @property
    def version(self) -> int:
        return self.conn.execute("PRAGMA user_version").fetchone()[0]

    def migrate(self):
        with self.lock:
            v = self.version
            for i in range(v, len(MIGRATIONS)):
                try:
                    self.conn.executescript(f"BEGIN IMMEDIATE;\n{MIGRATIONS[i]}\nPRAGMA user_version={i + 1};\nCOMMIT;")
                except Exception:
                    if self.conn.in_transaction:
                        self.conn.execute("ROLLBACK")
                    raise

    # helpers ------------------------------------------------------------------
    def q(self, sql: str, args=()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql: str, args=()) -> dict | None:
        with self.lock:
            r = self.conn.execute(sql, args).fetchone()
            return dict(r) if r else None

    def x(self, sql: str, args=()) -> int:
        """Execute a write; returns lastrowid for INSERT, rowcount otherwise."""
        with self.lock:
            c = self.conn.execute(sql, args)
            return c.lastrowid if sql.lstrip().upper().startswith("INSERT") else c.rowcount

    @contextmanager
    def tx(self):
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    def close(self):
        with self.lock:
            self.conn.close()
