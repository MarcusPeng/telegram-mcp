from telegram_mcp.multiuser.web import csrf


def test_sign_is_deterministic_for_same_cookie_value():
    cookie_value = csrf.new_cookie_value()
    assert csrf.sign(cookie_value) == csrf.sign(cookie_value)


def test_verify_accepts_matching_pair():
    cookie_value = csrf.new_cookie_value()
    token = csrf.sign(cookie_value)
    assert csrf.verify(cookie_value, token) is True


def test_verify_rejects_mismatched_token():
    cookie_value = csrf.new_cookie_value()
    other_cookie_value = csrf.new_cookie_value()
    forged_token = csrf.sign(other_cookie_value)
    assert csrf.verify(cookie_value, forged_token) is False


def test_verify_rejects_missing_cookie_or_token():
    cookie_value = csrf.new_cookie_value()
    token = csrf.sign(cookie_value)
    assert csrf.verify(None, token) is False
    assert csrf.verify(cookie_value, None) is False
    assert csrf.verify(None, None) is False
