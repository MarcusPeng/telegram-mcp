import base64

from telegram_mcp.multiuser import crypto, jwt_tokens


def test_issue_and_decode_access_token():
    token, jti, expires_at = jwt_tokens.issue_access_token(
        telegram_user_id=42,
        client_id="client-1",
        scopes=["telegram"],
        issuer="http://example.test",
        ttl_seconds=60,
    )
    claims = jwt_tokens.decode_access_token(token)
    assert claims is not None
    assert claims["sub"] == "42"
    assert claims["client_id"] == "client-1"
    assert claims["scope"] == "telegram"
    assert claims["jti"] == jti
    assert claims["exp"] == expires_at


def test_decode_rejects_expired_token():
    token, _jti, _exp = jwt_tokens.issue_access_token(
        telegram_user_id=42,
        client_id="c",
        scopes=[],
        issuer="http://example.test",
        ttl_seconds=-1,
    )
    assert jwt_tokens.decode_access_token(token) is None


def test_decode_rejects_garbage_token():
    assert jwt_tokens.decode_access_token("not-a-real-token") is None


def test_decode_rejects_token_signed_with_different_key(monkeypatch):
    token, _jti, _exp = jwt_tokens.issue_access_token(
        telegram_user_id=42, client_id="c", scopes=[], issuer="http://example.test"
    )
    monkeypatch.setenv("TELEGRAM_MCP_MASTER_KEY", base64.b64encode(b"1" * 32).decode())
    crypto._master_key = None
    assert jwt_tokens.decode_access_token(token) is None
