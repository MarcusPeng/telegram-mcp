"""Shared fixtures for telegram_mcp.multiuser tests.

Each test gets a fresh in-memory SQLite DB and a fixed, valid master key, so
encryption/DB state never leaks between tests.
"""

import base64

import pytest

from telegram_mcp.multiuser import client_pool, crypto, db

_TEST_MASTER_KEY = base64.b64encode(b"0" * 32).decode()


@pytest.fixture(autouse=True)
def _reset_multiuser_state(monkeypatch):
    monkeypatch.setenv("TELEGRAM_MCP_MASTER_KEY", _TEST_MASTER_KEY)
    monkeypatch.setenv("TELEGRAM_MCP_DB_PATH", ":memory:")
    monkeypatch.setenv("TELEGRAM_MCP_PUBLIC_URL", "http://127.0.0.1:8000")
    crypto._master_key = None
    db._connection = None
    client_pool._pool = None
    yield
    crypto._master_key = None
    db._connection = None
    client_pool._pool = None


@pytest.fixture
def conn():
    connection = db.get_connection()
    db.init_schema(connection)
    return connection
