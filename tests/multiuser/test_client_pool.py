import pytest

from telegram_mcp.multiuser import client_pool, principals


class _FakeTelegramClient:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.disconnected = False

    async def disconnect(self):
        self.disconnected = True


@pytest.fixture(autouse=True)
def _fake_telegram_client(monkeypatch):
    monkeypatch.setattr(client_pool, "TelegramClient", _FakeTelegramClient)
    monkeypatch.setattr(client_pool, "StringSession", lambda value: f"StringSession:{value}")


def test_get_or_create_returns_same_instance(conn):
    principals.upsert_principal(
        conn, telegram_user_id=111, api_id=12345, api_hash="abc", session_string="sess", phone=None
    )
    pool = client_pool.ClientPool()
    client1 = pool.get_or_create(111)
    client2 = pool.get_or_create(111)
    assert client1 is client2


def test_get_or_create_raises_when_not_linked(conn):
    pool = client_pool.ClientPool()
    with pytest.raises(ValueError, match="No Telegram account linked"):
        pool.get_or_create(999)


@pytest.mark.asyncio
async def test_evict_idle_disconnects_stale_clients(conn):
    principals.upsert_principal(
        conn, telegram_user_id=111, api_id=12345, api_hash="abc", session_string="sess", phone=None
    )
    pool = client_pool.ClientPool(idle_timeout_seconds=60)
    client = pool.get_or_create(111)
    pool._last_used[111] = 0  # force "long idle" deterministically

    await pool.evict_idle()

    assert client.disconnected is True
    assert 111 not in pool._clients


@pytest.mark.asyncio
async def test_disconnect_all(conn):
    principals.upsert_principal(
        conn, telegram_user_id=111, api_id=12345, api_hash="abc", session_string="sess", phone=None
    )
    pool = client_pool.ClientPool()
    client = pool.get_or_create(111)

    await pool.disconnect_all()

    assert client.disconnected is True
    assert pool._clients == {}


def test_get_pool_reads_idle_timeout_env(monkeypatch):
    monkeypatch.setenv("TELEGRAM_MCP_CLIENT_IDLE_SECONDS", "42")
    pool = client_pool.get_pool()
    assert pool._idle_timeout == 42


def _clear_proxy_env(monkeypatch):
    import os

    for key in list(os.environ):
        if key.startswith("TELEGRAM_PROXY_"):
            monkeypatch.delenv(key, raising=False)


def test_proxy_kwargs_empty_when_unset(monkeypatch):
    _clear_proxy_env(monkeypatch)
    assert client_pool._proxy_kwargs() == {}


def test_proxy_kwargs_applied_to_constructed_client(conn, monkeypatch):
    _clear_proxy_env(monkeypatch)
    import sys
    import types

    monkeypatch.setitem(sys.modules, "python_socks", types.ModuleType("python_socks"))
    monkeypatch.setenv("TELEGRAM_PROXY_TYPE", "socks5")
    monkeypatch.setenv("TELEGRAM_PROXY_HOST", "proxy.example")
    monkeypatch.setenv("TELEGRAM_PROXY_PORT", "1080")

    principals.upsert_principal(
        conn, telegram_user_id=111, api_id=12345, api_hash="abc", session_string="sess", phone=None
    )
    pool = client_pool.ClientPool()
    client = pool.get_or_create(111)

    assert client.kwargs["proxy"] == {
        "proxy_type": "socks5",
        "addr": "proxy.example",
        "port": 1080,
        "rdns": True,
    }


def test_proxy_kwargs_ignores_per_label_override(monkeypatch):
    """HTTP mode has no account labels -- a stray _<LABEL> override must not apply."""
    _clear_proxy_env(monkeypatch)
    monkeypatch.setenv("TELEGRAM_PROXY_TYPE_WORK", "socks5")
    monkeypatch.setenv("TELEGRAM_PROXY_HOST_WORK", "proxy.example")
    monkeypatch.setenv("TELEGRAM_PROXY_PORT_WORK", "1080")
    assert client_pool._proxy_kwargs() == {}
