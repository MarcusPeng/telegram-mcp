"""SQLite storage for HTTP multi-user mode.

Holds OAuth protocol state (registered clients, authorization codes, refresh
tokens, revocations) and linked Telegram principals. Only used when
TELEGRAM_MCP_TRANSPORT=http; stdio mode never calls into this module.
"""

import os
import sqlite3
import threading

_DEFAULT_DB_PATH = "./telegram_mcp.db"

_lock = threading.Lock()
_connection: sqlite3.Connection | None = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS telegram_principals (
    telegram_user_id INTEGER PRIMARY KEY,
    api_id_enc BLOB NOT NULL,
    api_hash_enc BLOB NOT NULL,
    session_enc BLOB NOT NULL,
    phone TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    raw_metadata TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    telegram_user_id INTEGER NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    redirect_uri_provided_explicitly INTEGER NOT NULL,
    resource TEXT,
    expires_at REAL NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    telegram_user_id INTEGER NOT NULL,
    scopes TEXT NOT NULL,
    expires_at INTEGER,
    created_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS oauth_revoked_jti (
    jti TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS browser_sessions (
    session_id TEXT PRIMARY KEY,
    telegram_user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
"""


def _db_path() -> str:
    return os.getenv("TELEGRAM_MCP_DB_PATH", _DEFAULT_DB_PATH)


def get_connection() -> sqlite3.Connection:
    """Return the process-wide SQLite connection, opening it on first use."""
    global _connection
    if _connection is None:
        with _lock:
            if _connection is None:
                conn = sqlite3.connect(_db_path(), check_same_thread=False)
                # Deliberately not WAL: SQLite's own docs advise against WAL
                # on network filesystems (NFS/CephFS/etc.) due to unreliable
                # mmap/locking support, and a single-process, single-connection
                # deployment (see get_pool()'s replicas=1 requirement) doesn't
                # need WAL's concurrent-reader benefit anyway. The default
                # rollback-journal mode is slower under heavy concurrency but
                # safe on any filesystem.
                conn.row_factory = sqlite3.Row
                _connection = conn
    return _connection


def init_schema(conn: sqlite3.Connection) -> None:
    """Idempotently create all tables. Safe to call on every startup."""
    conn.executescript(_SCHEMA)
    conn.commit()
