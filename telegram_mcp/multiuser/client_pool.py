"""Per-principal TelegramClient pool for HTTP multi-user mode.

Plays the same role as the global `clients` dict in stdio mode, but builds
one TelegramClient per linked Telegram principal lazily (on first tool call)
instead of reading every account from env vars at startup. Idle clients are
evicted periodically so steady-state open Telegram connections track "users
active recently," not "every user who ever linked."
"""

import asyncio
import os
import time
from typing import Dict, Optional

from telethon import TelegramClient
from telethon.sessions import StringSession

from telegram_mcp import runtime as _runtime
from telegram_mcp.client_identity import client_identity_kwargs
from telegram_mcp.multiuser import db, principals


def _proxy_kwargs() -> Dict[str, object]:
    """Global (unsuffixed) TELEGRAM_PROXY_* config, applied to every user.

    HTTP multi-user mode has no per-account labels to override the proxy
    per-user with -- a proxy here is an operator/network-level setting (e.g.
    Telegram is blocked from this server's network), so it applies uniformly.
    """
    proxy, connection = _runtime._build_proxy_for_label(None)
    kwargs: Dict[str, object] = {}
    if proxy is not None:
        kwargs["proxy"] = proxy
    if connection is not None:
        kwargs["connection"] = connection
    return kwargs


class ClientPool:
    def __init__(self, idle_timeout_seconds: int = 900):
        self._idle_timeout = idle_timeout_seconds
        self._clients: Dict[int, TelegramClient] = {}
        self._last_used: Dict[int, float] = {}

    def get_or_create(self, telegram_user_id: int) -> TelegramClient:
        """Return this principal's TelegramClient, constructing it on first use.

        Does not connect -- callers go through the existing ensure_connected()
        helper in runtime.py, exactly as stdio-mode clients already do.
        """
        client = self._clients.get(telegram_user_id)
        if client is None:
            principal = principals.get_principal(db.get_connection(), telegram_user_id)
            if principal is None:
                raise ValueError(
                    "No Telegram account linked for this token. "
                    "Complete the Telegram login flow first."
                )
            client = TelegramClient(
                StringSession(principal.session_string),
                principal.api_id,
                principal.api_hash,
                **client_identity_kwargs(),
                **_proxy_kwargs(),
            )
            self._clients[telegram_user_id] = client
        self._last_used[telegram_user_id] = time.time()
        return client

    async def evict(self, telegram_user_id: int) -> None:
        client = self._clients.pop(telegram_user_id, None)
        self._last_used.pop(telegram_user_id, None)
        if client is not None:
            try:
                await client.disconnect()
            except Exception:
                pass

    async def evict_idle(self) -> None:
        now = time.time()
        stale = [
            uid
            for uid, last_used in self._last_used.items()
            if now - last_used > self._idle_timeout
        ]
        for uid in stale:
            await self.evict(uid)

    async def run_idle_eviction_loop(self, interval_seconds: int = 60) -> None:
        while True:
            await asyncio.sleep(interval_seconds)
            await self.evict_idle()

    async def disconnect_all(self) -> None:
        for uid in list(self._clients.keys()):
            await self.evict(uid)


_pool: Optional[ClientPool] = None


def get_pool() -> ClientPool:
    global _pool
    if _pool is None:
        idle_seconds = int(os.getenv("TELEGRAM_MCP_CLIENT_IDLE_SECONDS", "900"))
        _pool = ClientPool(idle_timeout_seconds=idle_seconds)
    return _pool
