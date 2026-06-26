from urllib.parse import parse_qs, urlparse

import pytest
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull

from telegram_mcp.multiuser import jwt_tokens, oauth_provider
from telegram_mcp.multiuser.oauth_provider import TelegramOAuthProvider


def _client_info(client_id: str = "client-1") -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=["http://127.0.0.1:9999/callback"],
        token_endpoint_auth_method="client_secret_post",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="telegram",
        client_name="Test Client",
    )


@pytest.mark.asyncio
async def test_register_and_get_client(conn):
    provider = TelegramOAuthProvider()
    info = _client_info()
    await provider.register_client(info)

    loaded = await provider.get_client("client-1")
    assert loaded is not None
    assert loaded.client_id == "client-1"
    assert str(loaded.redirect_uris[0]) == "http://127.0.0.1:9999/callback"


@pytest.mark.asyncio
async def test_get_client_returns_none_when_missing(conn):
    provider = TelegramOAuthProvider()
    assert await provider.get_client("missing") is None


@pytest.mark.asyncio
async def test_authorize_redirects_to_telegram_login(conn):
    provider = TelegramOAuthProvider()
    client = _client_info()
    params = AuthorizationParams(
        state="xyz",
        scopes=["telegram"],
        code_challenge="challenge123",
        redirect_uri="http://127.0.0.1:9999/callback",
        redirect_uri_provided_explicitly=True,
    )
    url = await provider.authorize(client, params)
    assert url.startswith("http://127.0.0.1:8000/telegram-login?")
    query = parse_qs(urlparse(url).query)
    assert query["client_id"] == ["client-1"]
    assert query["code_challenge"] == ["challenge123"]
    assert query["state"] == ["xyz"]


def test_issue_authorization_code(conn):
    redirect_url = oauth_provider.issue_authorization_code(
        telegram_user_id=999,
        client_id="client-1",
        redirect_uri="http://127.0.0.1:9999/callback",
        state="xyz",
        scopes=["telegram"],
        code_challenge="challenge123",
        redirect_uri_provided_explicitly=True,
        resource=None,
    )
    query = parse_qs(urlparse(redirect_url).query)
    assert "code" in query
    assert query["state"] == ["xyz"]


@pytest.mark.asyncio
async def test_full_authorization_and_refresh_round_trip(conn):
    provider = TelegramOAuthProvider()
    client = _client_info()
    await provider.register_client(client)

    redirect_url = oauth_provider.issue_authorization_code(
        telegram_user_id=999,
        client_id="client-1",
        redirect_uri="http://127.0.0.1:9999/callback",
        state="xyz",
        scopes=["telegram"],
        code_challenge="challenge123",
        redirect_uri_provided_explicitly=True,
        resource=None,
    )
    code = parse_qs(urlparse(redirect_url).query)["code"][0]

    loaded_code = await provider.load_authorization_code(client, code)
    assert loaded_code is not None
    assert loaded_code.telegram_user_id == 999

    token = await provider.exchange_authorization_code(client, loaded_code)
    assert token.access_token
    assert token.refresh_token
    assert token.scope == "telegram"

    # Single use: the code is gone after exchange.
    assert await provider.load_authorization_code(client, code) is None

    claims = jwt_tokens.decode_access_token(token.access_token)
    assert claims["sub"] == "999"

    access_token_obj = await provider.load_access_token(token.access_token)
    assert access_token_obj is not None
    assert access_token_obj.telegram_user_id == 999

    refresh_token_obj = await provider.load_refresh_token(client, token.refresh_token)
    assert refresh_token_obj is not None
    assert refresh_token_obj.telegram_user_id == 999

    new_token = await provider.exchange_refresh_token(client, refresh_token_obj, ["telegram"])
    assert new_token.access_token != token.access_token
    assert new_token.refresh_token != token.refresh_token

    # Rotation revokes the old refresh token.
    assert await provider.load_refresh_token(client, token.refresh_token) is None

    new_access_obj = await provider.load_access_token(new_token.access_token)
    await provider.revoke_token(new_access_obj)
    assert await provider.load_access_token(new_token.access_token) is None


@pytest.mark.asyncio
async def test_revoke_refresh_token(conn):
    provider = TelegramOAuthProvider()
    client = _client_info()
    await provider.register_client(client)

    redirect_url = oauth_provider.issue_authorization_code(
        telegram_user_id=999,
        client_id="client-1",
        redirect_uri="http://127.0.0.1:9999/callback",
        state=None,
        scopes=["telegram"],
        code_challenge="challenge123",
        redirect_uri_provided_explicitly=True,
        resource=None,
    )
    code = parse_qs(urlparse(redirect_url).query)["code"][0]
    loaded_code = await provider.load_authorization_code(client, code)
    token = await provider.exchange_authorization_code(client, loaded_code)

    refresh_token_obj = await provider.load_refresh_token(client, token.refresh_token)
    await provider.revoke_token(refresh_token_obj)
    assert await provider.load_refresh_token(client, token.refresh_token) is None
