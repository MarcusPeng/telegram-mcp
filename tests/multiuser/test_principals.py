from telegram_mcp.multiuser import principals


def test_upsert_and_get_principal(conn):
    principals.upsert_principal(
        conn,
        telegram_user_id=111,
        api_id=12345,
        api_hash="abc123",
        session_string="session-string-value",
        phone="15551234567",
    )
    principal = principals.get_principal(conn, 111)
    assert principal.telegram_user_id == 111
    assert principal.api_id == 12345
    assert principal.api_hash == "abc123"
    assert principal.session_string == "session-string-value"
    assert principal.phone == "15551234567"


def test_upsert_overwrites_existing_principal(conn):
    principals.upsert_principal(
        conn, telegram_user_id=111, api_id=1, api_hash="a", session_string="s1", phone=None
    )
    principals.upsert_principal(
        conn, telegram_user_id=111, api_id=2, api_hash="b", session_string="s2", phone="999"
    )
    principal = principals.get_principal(conn, 111)
    assert principal.api_id == 2
    assert principal.api_hash == "b"
    assert principal.session_string == "s2"
    assert principal.phone == "999"


def test_get_principal_returns_none_when_missing(conn):
    assert principals.get_principal(conn, 999) is None


def test_principal_exists(conn):
    assert principals.principal_exists(conn, 111) is False
    principals.upsert_principal(
        conn, telegram_user_id=111, api_id=1, api_hash="a", session_string="s", phone=None
    )
    assert principals.principal_exists(conn, 111) is True
