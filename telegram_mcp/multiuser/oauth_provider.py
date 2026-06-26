"""Self-contained OAuth Authorization Server where a Telegram login *is* the login.

There is no separate username/password account system. ``authorize()`` always
redirects to our own ``/telegram-login`` page (registered as a
``@mcp.custom_route`` in ``web/telegram_login.py``, so it bypasses Bearer-token
auth like any other OAuth-flow page). That page drives Telegram's own QR or
phone+code(+2FA) login using the end user's own ``api_id``/``api_hash``; once
it succeeds, it calls ``issue_authorization_code()`` below to mint the code and
redirect back to the MCP client's ``redirect_uri`` -- completing the OAuth
flow. PKCE itself needs no work here: the SDK's token handler validates
``code_verifier`` against the stored ``code_challenge`` before
``exchange_authorization_code`` is ever invoked.
"""

import json
import secrets
import time
from typing import List, Optional

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from telegram_mcp.multiuser import db, jwt_tokens
from telegram_mcp.multiuser.settings import public_url

_AUTH_CODE_TTL_SECONDS = 600
_ACCESS_TOKEN_TTL_SECONDS = 3600
_REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 90  # 90 days


class TelegramAuthorizationCode(AuthorizationCode):
    telegram_user_id: int


class TelegramRefreshToken(RefreshToken):
    telegram_user_id: int


class TelegramAccessToken(AccessToken):
    telegram_user_id: int


class TelegramOAuthProvider(OAuthAuthorizationServerProvider):
    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        conn = db.get_connection()
        row = conn.execute(
            "SELECT raw_metadata FROM oauth_clients WHERE client_id = ?", (client_id,)
        ).fetchone()
        if row is None:
            return None
        return OAuthClientInformationFull.model_validate_json(row["raw_metadata"])

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        conn = db.get_connection()
        conn.execute(
            "INSERT INTO oauth_clients (client_id, raw_metadata, created_at) VALUES (?, ?, ?)",
            (client_info.client_id, client_info.model_dump_json(), int(time.time())),
        )
        conn.commit()

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        # authorize() only returns a redirect URL -- it has no access to
        # cookies, so it can't itself decide "is this browser already logged
        # in." That decision happens in /telegram-login (web/telegram_login.py),
        # which does see the request's cookies.
        from urllib.parse import urlencode

        query = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "state": params.state,
            "code_challenge": params.code_challenge,
            "scope": " ".join(params.scopes or []),
            "resource": params.resource,
            "redirect_uri_provided_explicitly": (
                "1" if params.redirect_uri_provided_explicitly else "0"
            ),
        }
        clean_query = {k: v for k, v in query.items() if v is not None}
        return f"{public_url()}/telegram-login?{urlencode(clean_query)}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> Optional[TelegramAuthorizationCode]:
        conn = db.get_connection()
        row = conn.execute(
            "SELECT * FROM oauth_authorization_codes WHERE code = ? AND client_id = ?",
            (authorization_code, client.client_id),
        ).fetchone()
        if row is None:
            return None
        if row["expires_at"] < time.time():
            conn.execute(
                "DELETE FROM oauth_authorization_codes WHERE code = ?", (authorization_code,)
            )
            conn.commit()
            return None
        return TelegramAuthorizationCode(
            code=row["code"],
            scopes=json.loads(row["scopes"]),
            expires_at=row["expires_at"],
            client_id=row["client_id"],
            code_challenge=row["code_challenge"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_provided_explicitly=bool(row["redirect_uri_provided_explicitly"]),
            resource=row["resource"],
            telegram_user_id=row["telegram_user_id"],
        )

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: TelegramAuthorizationCode,
    ) -> OAuthToken:
        conn = db.get_connection()
        # Single use: delete on exchange.
        conn.execute(
            "DELETE FROM oauth_authorization_codes WHERE code = ?", (authorization_code.code,)
        )
        conn.commit()
        return _issue_token_pair(
            client_id=client.client_id,
            telegram_user_id=authorization_code.telegram_user_id,
            scopes=authorization_code.scopes,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> Optional[TelegramRefreshToken]:
        conn = db.get_connection()
        row = conn.execute(
            "SELECT * FROM oauth_refresh_tokens WHERE token = ? AND client_id = ?",
            (refresh_token, client.client_id),
        ).fetchone()
        if row is None or row["revoked"]:
            return None
        if row["expires_at"] is not None and row["expires_at"] < time.time():
            return None
        return TelegramRefreshToken(
            token=row["token"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            expires_at=row["expires_at"],
            telegram_user_id=row["telegram_user_id"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: TelegramRefreshToken,
        scopes: List[str],
    ) -> OAuthToken:
        conn = db.get_connection()
        # Rotate: the old refresh token is revoked, a new one is issued below.
        conn.execute(
            "UPDATE oauth_refresh_tokens SET revoked = 1 WHERE token = ?",
            (refresh_token.token,),
        )
        conn.commit()
        return _issue_token_pair(
            client_id=client.client_id,
            telegram_user_id=refresh_token.telegram_user_id,
            scopes=scopes or refresh_token.scopes,
        )

    async def load_access_token(self, token: str) -> Optional[TelegramAccessToken]:
        claims = jwt_tokens.decode_access_token(token)
        if claims is None:
            return None
        conn = db.get_connection()
        revoked = conn.execute(
            "SELECT 1 FROM oauth_revoked_jti WHERE jti = ?", (claims["jti"],)
        ).fetchone()
        if revoked is not None:
            return None
        return TelegramAccessToken(
            token=token,
            client_id=claims["client_id"],
            scopes=claims["scope"].split() if claims["scope"] else [],
            expires_at=claims["exp"],
            telegram_user_id=int(claims["sub"]),
        )

    async def revoke_token(self, token) -> None:
        conn = db.get_connection()
        if isinstance(token, RefreshToken):
            conn.execute(
                "UPDATE oauth_refresh_tokens SET revoked = 1 WHERE token = ?", (token.token,)
            )
            conn.commit()
            return
        if isinstance(token, AccessToken):
            claims = jwt_tokens.decode_access_token(token.token)
            if claims is None:
                return
            conn.execute(
                "INSERT OR REPLACE INTO oauth_revoked_jti (jti, expires_at) VALUES (?, ?)",
                (claims["jti"], claims["exp"]),
            )
            conn.commit()


def _issue_token_pair(*, client_id: str, telegram_user_id: int, scopes: List[str]) -> OAuthToken:
    access_token, _jti, _expires_at = jwt_tokens.issue_access_token(
        telegram_user_id=telegram_user_id,
        client_id=client_id,
        scopes=scopes,
        issuer=public_url(),
        ttl_seconds=_ACCESS_TOKEN_TTL_SECONDS,
    )
    refresh_token = secrets.token_urlsafe(32)
    now = int(time.time())
    conn = db.get_connection()
    conn.execute(
        "INSERT INTO oauth_refresh_tokens "
        "(token, client_id, telegram_user_id, scopes, expires_at, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            refresh_token,
            client_id,
            telegram_user_id,
            json.dumps(scopes),
            now + _REFRESH_TOKEN_TTL_SECONDS,
            now,
        ),
    )
    conn.commit()
    return OAuthToken(
        access_token=access_token,
        token_type="Bearer",
        expires_in=_ACCESS_TOKEN_TTL_SECONDS,
        refresh_token=refresh_token,
        scope=" ".join(scopes),
    )


def issue_authorization_code(
    *,
    telegram_user_id: int,
    client_id: str,
    redirect_uri: str,
    state: Optional[str],
    scopes: List[str],
    code_challenge: str,
    redirect_uri_provided_explicitly: bool,
    resource: Optional[str],
) -> str:
    """Mint an authorization code and return the redirect back to the MCP client.

    Called by web/telegram_login.py once Telegram login (or an existing
    browser session for a previously-linked account) is confirmed.
    """
    code = secrets.token_urlsafe(32)
    now = time.time()
    conn = db.get_connection()
    conn.execute(
        """
        INSERT INTO oauth_authorization_codes
            (code, client_id, telegram_user_id, scopes, code_challenge, redirect_uri,
             redirect_uri_provided_explicitly, resource, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            code,
            client_id,
            telegram_user_id,
            json.dumps(scopes),
            code_challenge,
            redirect_uri,
            1 if redirect_uri_provided_explicitly else 0,
            resource,
            now + _AUTH_CODE_TTL_SECONDS,
            int(now),
        ),
    )
    conn.commit()
    return construct_redirect_uri(redirect_uri, code=code, state=state)
