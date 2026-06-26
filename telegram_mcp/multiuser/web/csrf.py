"""CSRF protection for the Telegram-login web flow (double-submit cookie).

No server-side storage: the cookie holds a random value, and every form
embeds an HMAC of that value (computed server-side from the request's own
cookie when the page is rendered). A POST is only accepted if the submitted
HMAC matches the one derivable from the request's own CSRF cookie.
"""

import hashlib
import hmac
import secrets
from typing import Optional

from telegram_mcp.multiuser import crypto

CSRF_COOKIE_NAME = "tg_csrf"


def _signing_key() -> bytes:
    return hmac.new(crypto.master_key(), b"csrf-signing", hashlib.sha256).digest()


def new_cookie_value() -> str:
    return secrets.token_urlsafe(24)


def sign(cookie_value: str) -> str:
    return hmac.new(_signing_key(), cookie_value.encode("utf-8"), hashlib.sha256).hexdigest()


def verify(cookie_value: Optional[str], submitted_token: Optional[str]) -> bool:
    if not cookie_value or not submitted_token:
        return False
    return hmac.compare_digest(sign(cookie_value), submitted_token)
