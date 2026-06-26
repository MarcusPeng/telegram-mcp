"""AES-256-GCM encryption at rest for per-principal Telegram credentials.

A linked Telegram session string is equivalent to full account takeover, and
the user-supplied api_id/api_hash are themselves credentials, so all three
are encrypted before being written to telegram_principals. Keyed by
TELEGRAM_MCP_MASTER_KEY (32 raw bytes, base64-encoded) -- an operator-supplied
secret, never generated or persisted by this code. Losing the key makes every
stored row permanently undecryptable; key rotation is not supported.
"""

import base64
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LEN = 12

_master_key: Optional[bytes] = None


def _load_master_key() -> bytes:
    raw = os.getenv("TELEGRAM_MCP_MASTER_KEY")
    if not raw:
        raise SystemExit(
            "TELEGRAM_MCP_MASTER_KEY is required when TELEGRAM_MCP_TRANSPORT=http. "
            "Generate one with: openssl rand -base64 32"
        )
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise SystemExit("TELEGRAM_MCP_MASTER_KEY must be valid base64.") from exc
    if len(key) != 32:
        raise SystemExit("TELEGRAM_MCP_MASTER_KEY must decode to exactly 32 bytes.")
    return key


def master_key() -> bytes:
    """Return the cached master key, loading and validating it on first use."""
    global _master_key
    if _master_key is None:
        _master_key = _load_master_key()
    return _master_key


def _aad(telegram_user_id: int, field: str) -> bytes:
    # Binds ciphertext to (telegram_user_id, field) so a row can't be copied
    # to a different user/column in the DB and still decrypt successfully.
    return f"{telegram_user_id}:{field}".encode("utf-8")


def encrypt_field(plaintext: str, *, telegram_user_id: int, field: str) -> bytes:
    aesgcm = AESGCM(master_key())
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), _aad(telegram_user_id, field))
    return nonce + ciphertext


def decrypt_field(blob: bytes, *, telegram_user_id: int, field: str) -> str:
    aesgcm = AESGCM(master_key())
    nonce, ciphertext = bytes(blob[:_NONCE_LEN]), bytes(blob[_NONCE_LEN:])
    plaintext = aesgcm.decrypt(nonce, ciphertext, _aad(telegram_user_id, field))
    return plaintext.decode("utf-8")
