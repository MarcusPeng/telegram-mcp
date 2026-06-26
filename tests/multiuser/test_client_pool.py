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
