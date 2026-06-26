import base64

import pytest

from telegram_mcp.multiuser import crypto


def test_encrypt_decrypt_round_trip():
    blob = crypto.encrypt_field("secret-value", telegram_user_id=42, field="session")
    assert crypto.decrypt_field(blob, telegram_user_id=42, field="session") == "secret-value"


def test_decrypt_fails_with_wrong_user_id():
    blob = crypto.encrypt_field("secret-value", telegram_user_id=42, field="session")
    with pytest.raises(Exception):
        crypto.decrypt_field(blob, telegram_user_id=43, field="session")


def test_decrypt_fails_with_wrong_field():
    blob = crypto.encrypt_field("secret-value", telegram_user_id=42, field="session")
    with pytest.raises(Exception):
        crypto.decrypt_field(blob, telegram_user_id=42, field="api_id")


def test_decrypt_fails_with_tampered_ciphertext():
    blob = bytearray(crypto.encrypt_field("secret-value", telegram_user_id=42, field="session"))
    blob[-1] ^= 0xFF
    with pytest.raises(Exception):
        crypto.decrypt_field(bytes(blob), telegram_user_id=42, field="session")


def test_master_key_required(monkeypatch):
    monkeypatch.delenv("TELEGRAM_MCP_MASTER_KEY", raising=False)
    crypto._master_key = None
    with pytest.raises(SystemExit):
        crypto.master_key()


def test_master_key_must_be_32_bytes(monkeypatch):
    monkeypatch.setenv("TELEGRAM_MCP_MASTER_KEY", base64.b64encode(b"short").decode())
    crypto._master_key = None
    with pytest.raises(SystemExit):
        crypto.master_key()


def test_master_key_must_be_valid_base64(monkeypatch):
    monkeypatch.setenv("TELEGRAM_MCP_MASTER_KEY", "not-valid-base64!!!")
    crypto._master_key = None
    with pytest.raises(SystemExit):
        crypto.master_key()
