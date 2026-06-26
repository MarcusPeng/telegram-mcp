"""Self-contained JWT access tokens for HTTP multi-user mode.

Access tokens are not stored server-side: every tool call verifies a
signature instead of reading a DB row. Revocation is handled separately by a
small jti denylist (see db.py: oauth_revoked_jti), checked only inside
oauth_provider.TelegramOAuthProvider.load_access_token(). The signing key is
derived from TELEGRAM_MCP_MASTER_KEY so operators only manage one secret.
"""

import hashlib
import hmac
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import jwt

from telegram_mcp.multiuser import crypto

_ALGORITHM = "HS256"


def _signing_key() -> bytes:
    return hmac.new(crypto.master_key(), b"jwt-signing", hashlib.sha256).digest()


def issue_access_token(
    *,
    telegram_user_id: int,
    client_id: str,
    scopes: List[str],
    issuer: str,
    ttl_seconds: int = 3600,
) -> Tuple[str, str, int]:
    """Mint a signed access token. Returns (token, jti, expires_at_epoch)."""
    now = int(time.time())
    expires_at = now + ttl_seconds
    jti = uuid.uuid4().hex
    claims = {
        "sub": str(telegram_user_id),
        "client_id": client_id,
        "scope": " ".join(scopes),
        "jti": jti,
        "iat": now,
        "exp": expires_at,
        "iss": issuer,
    }
    token = jwt.encode(claims, _signing_key(), algorithm=_ALGORITHM)
    return token, jti, expires_at


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify signature + expiry and return claims, or None on any failure."""
    try:
        return jwt.decode(token, _signing_key(), algorithms=[_ALGORITHM])
    except jwt.PyJWTError:
        return None
