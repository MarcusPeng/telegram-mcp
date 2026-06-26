"""Browser-facing Telegram-login + OAuth-consent flow.

This is the only way an end user authenticates in HTTP multi-user mode:
oauth_provider.TelegramOAuthProvider.authorize() always redirects here. There
is no separate username/password step -- completing Telegram's own QR or
phone+code(+2FA) login *is* logging in. Routes are registered via
@mcp.custom_route(), so the SDK never wraps them with Bearer-token auth (see
mcp.server.fastmcp's docstring: custom routes are "part of authorization
flows or intended to be public").

Drives Telethon with the asyncio-native client (not telethon.sync) since
these are async Starlette route handlers, mirroring the QR refresh-on-expiry
and phone/2FA handling already prototyped in session_string_generator.py.
"""

import asyncio
import base64
import io
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import qrcode
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from telethon import TelegramClient, errors
from telethon.sessions import StringSession

from telegram_mcp.client_identity import client_identity_kwargs
from telegram_mcp.multiuser import db, oauth_provider, principals
from telegram_mcp.multiuser.oauth_provider import TelegramOAuthProvider
from telegram_mcp.multiuser.web import csrf, templates
from telegram_mcp.runtime import mcp

_OAUTH_PARAM_NAMES = (
    "client_id",
    "redirect_uri",
    "state",
    "code_challenge",
    "scope",
    "resource",
    "redirect_uri_provided_explicitly",
)

_FLOW_TTL_SECONDS = 300
_BROWSER_SESSION_COOKIE_NAME = "tg_session"
_BROWSER_SESSION_TTL_SECONDS = 60 * 60 * 24 * 30  # 30 days

# Ephemeral login state (live TelegramClient + QR object) can't be persisted
# to SQLite -- a socket isn't serializable -- so it lives in memory for the
# lifetime of one login attempt (a few minutes at most).
_pending_flows: Dict[str, Dict[str, Any]] = {}

_provider = TelegramOAuthProvider()


def _oauth_params_from_mapping(mapping: Any) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for name in _OAUTH_PARAM_NAMES:
        value = mapping.get(name)
        if value:
            result[name] = value
    return result


def _secure_cookies() -> bool:
    from telegram_mcp.multiuser.settings import public_url

    return public_url().startswith("https://")


def _csrf_state(request: Request) -> Tuple[str, Optional[str]]:
    """Returns (csrf_token_to_embed_in_the_form, new_cookie_value_or_None)."""
    existing = request.cookies.get(csrf.CSRF_COOKIE_NAME)
    if existing:
        return csrf.sign(existing), None
    new_value = csrf.new_cookie_value()
    return csrf.sign(new_value), new_value


def _apply_csrf_cookie(response: Response, new_cookie_value: Optional[str]) -> None:
    if new_cookie_value:
        response.set_cookie(
            csrf.CSRF_COOKIE_NAME,
            new_cookie_value,
            httponly=True,
            samesite="lax",
            secure=_secure_cookies(),
            max_age=_FLOW_TTL_SECONDS,
        )


async def _verify_csrf(request: Request, form: Dict[str, str]) -> bool:
    cookie_value = request.cookies.get(csrf.CSRF_COOKIE_NAME)
    return csrf.verify(cookie_value, form.get("csrf_token"))


def _set_browser_session_cookie(response: Response, telegram_user_id: int) -> None:
    import secrets

    session_id = secrets.token_urlsafe(32)
    now = int(time.time())
    conn = db.get_connection()
    conn.execute(
        "INSERT INTO browser_sessions (session_id, telegram_user_id, expires_at, created_at) "
        "VALUES (?, ?, ?, ?)",
        (session_id, telegram_user_id, now + _BROWSER_SESSION_TTL_SECONDS, now),
    )
    conn.commit()
    response.set_cookie(
        _BROWSER_SESSION_COOKIE_NAME,
        session_id,
        httponly=True,
        samesite="lax",
        secure=_secure_cookies(),
        max_age=_BROWSER_SESSION_TTL_SECONDS,
    )


def _telegram_user_id_from_browser_session(request: Request) -> Optional[int]:
    session_id = request.cookies.get(_BROWSER_SESSION_COOKIE_NAME)
    if not session_id:
        return None
    conn = db.get_connection()
    row = conn.execute(
        "SELECT telegram_user_id FROM browser_sessions WHERE session_id = ? AND expires_at > ?",
        (session_id, int(time.time())),
    ).fetchone()
    return row["telegram_user_id"] if row else None


def _qr_data_uri(url: str) -> str:
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _qr_expired(qr: Any) -> bool:
    expires = qr.expires
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) >= expires


def _prune_stale_flows() -> None:
    now = time.time()
    stale = [
        flow_id
        for flow_id, flow in _pending_flows.items()
        if now - flow["created_at"] > _FLOW_TTL_SECONDS
    ]
    for flow_id in stale:
        _pending_flows.pop(flow_id, None)


def _render_connect_error(
    request: Request, oauth_params: Dict[str, str], message: str
) -> Response:
    csrf_token, new_cookie = _csrf_state(request)
    response = HTMLResponse(
        templates.render_connect_page(oauth_params, csrf_token, error=message), status_code=400
    )
    _apply_csrf_cookie(response, new_cookie)
    return response


async def _finalize_login(
    *,
    client: TelegramClient,
    api_id: int,
    api_hash: str,
    oauth_params: Dict[str, str],
) -> Response:
    """Common tail of every successful Telegram login.

    Persists the principal, mints the authorization code, sets the
    convenience browser-session cookie, and redirects back to the MCP
    client's redirect_uri.
    """
    me = await client.get_me()
    session_string = StringSession.save(client.session)
    telegram_user_id = me.id
    phone = getattr(me, "phone", None)

    principals.upsert_principal(
        db.get_connection(),
        telegram_user_id=telegram_user_id,
        api_id=api_id,
        api_hash=api_hash,
        session_string=session_string,
        phone=phone,
    )
    await client.disconnect()

    redirect_url = oauth_provider.issue_authorization_code(
        telegram_user_id=telegram_user_id,
        client_id=oauth_params["client_id"],
        redirect_uri=oauth_params["redirect_uri"],
        state=oauth_params.get("state"),
        scopes=oauth_params["scope"].split() if oauth_params.get("scope") else [],
        code_challenge=oauth_params["code_challenge"],
        redirect_uri_provided_explicitly=oauth_params.get("redirect_uri_provided_explicitly")
        == "1",
        resource=oauth_params.get("resource"),
    )
    response = RedirectResponse(redirect_url, status_code=302)
    _set_browser_session_cookie(response, telegram_user_id)
    return response


@mcp.custom_route("/telegram-login", methods=["GET"])
async def telegram_login_entry(request: Request) -> Response:
    oauth_params = _oauth_params_from_mapping(request.query_params)
    if not oauth_params.get("client_id") or not oauth_params.get("redirect_uri"):
        return HTMLResponse(templates.render_error("Missing OAuth parameters."), status_code=400)

    force_relogin = request.query_params.get("force_relogin") == "1"
    telegram_user_id = None if force_relogin else _telegram_user_id_from_browser_session(request)

    if telegram_user_id is not None:
        principal = principals.get_principal(db.get_connection(), telegram_user_id)
        if principal is not None:
            client_info = await _provider.get_client(oauth_params["client_id"])
            client_name = client_info.client_name if client_info else None
            csrf_token, new_cookie = _csrf_state(request)
            response = HTMLResponse(
                templates.render_consent_page(
                    oauth_params, csrf_token, principal.phone, client_name
                )
            )
            _apply_csrf_cookie(response, new_cookie)
            return response

    csrf_token, new_cookie = _csrf_state(request)
    response = HTMLResponse(templates.render_connect_page(oauth_params, csrf_token))
    _apply_csrf_cookie(response, new_cookie)
    return response


@mcp.custom_route("/telegram-login/start", methods=["POST"])
async def telegram_login_start(request: Request) -> Response:
    form = dict(await request.form())
    if not await _verify_csrf(request, form):
        return HTMLResponse(
            templates.render_error("Invalid or expired form submission. Please retry."),
            status_code=400,
        )

    oauth_params = _oauth_params_from_mapping(form)
    if not oauth_params.get("client_id") or not oauth_params.get("redirect_uri"):
        return HTMLResponse(templates.render_error("Missing OAuth parameters."), status_code=400)

    try:
        api_id = int(str(form.get("api_id", "")).strip())
    except ValueError:
        return _render_connect_error(request, oauth_params, "API ID must be a number.")
    api_hash = str(form.get("api_hash", "")).strip()
    if not api_hash:
        return _render_connect_error(request, oauth_params, "API Hash is required.")
    method = form.get("method", "qr")
    phone = str(form.get("phone", "")).strip() or None

    _prune_stale_flows()
    client = TelegramClient(StringSession(), api_id, api_hash, **client_identity_kwargs())
    try:
        await client.connect()
    except Exception as exc:
        return _render_connect_error(
            request, oauth_params, f"Could not connect to Telegram: {exc}"
        )

    flow: Dict[str, Any] = {
        "client": client,
        "api_id": api_id,
        "api_hash": api_hash,
        "oauth_params": oauth_params,
        "created_at": time.time(),
    }
    flow_id = uuid.uuid4().hex
    csrf_token, new_cookie = _csrf_state(request)

    if method == "phone":
        if not phone:
            await client.disconnect()
            return _render_connect_error(
                request, oauth_params, "Phone number is required for phone login."
            )
        try:
            await client.send_code_request(phone)
        except errors.FloodWaitError as exc:
            await client.disconnect()
            return _render_connect_error(
                request, oauth_params, f"Too many attempts; wait {exc.seconds} seconds."
            )
        except errors.PhoneNumberInvalidError:
            await client.disconnect()
            return _render_connect_error(request, oauth_params, "That phone number is invalid.")
        except errors.RPCError as exc:
            await client.disconnect()
            return _render_connect_error(
                request, oauth_params, f"Telegram rejected the API ID/Hash: {exc}"
            )
        flow["phone"] = phone
        _pending_flows[flow_id] = flow
        response = HTMLResponse(templates.render_code_form(oauth_params, flow_id, csrf_token))
        _apply_csrf_cookie(response, new_cookie)
        return response

    try:
        qr = await client.qr_login()
    except errors.RPCError as exc:
        await client.disconnect()
        return _render_connect_error(
            request, oauth_params, f"Telegram rejected the API ID/Hash: {exc}"
        )
    flow["qr"] = qr
    _pending_flows[flow_id] = flow
    response = HTMLResponse(templates.render_qr_page(qr.url, _qr_data_uri(qr.url), flow_id))
    _apply_csrf_cookie(response, new_cookie)
    return response


@mcp.custom_route("/telegram-login/qr-status", methods=["GET"])
async def telegram_login_qr_status(request: Request) -> Response:
    flow_id = request.query_params.get("flow_id", "")
    flow = _pending_flows.get(flow_id)
    if flow is None:
        return HTMLResponse(
            templates.render_error("This login attempt has expired. Please start again."),
            status_code=400,
        )

    client: TelegramClient = flow["client"]
    qr = flow["qr"]
    oauth_params = flow["oauth_params"]

    try:
        await qr.wait(timeout=1)
    except errors.SessionPasswordNeededError:
        csrf_token, new_cookie = _csrf_state(request)
        response = HTMLResponse(templates.render_password_form(oauth_params, flow_id, csrf_token))
        _apply_csrf_cookie(response, new_cookie)
        return response
    except asyncio.TimeoutError:
        if _qr_expired(qr):
            try:
                await qr.recreate()
            except Exception:
                _pending_flows.pop(flow_id, None)
                await client.disconnect()
                return HTMLResponse(
                    templates.render_error("QR login expired too many times. Please start again."),
                    status_code=400,
                )
        return HTMLResponse(templates.render_qr_page(qr.url, _qr_data_uri(qr.url), flow_id))

    _pending_flows.pop(flow_id, None)
    return await _finalize_login(
        client=client, api_id=flow["api_id"], api_hash=flow["api_hash"], oauth_params=oauth_params
    )


@mcp.custom_route("/telegram-login/code", methods=["POST"])
async def telegram_login_code(request: Request) -> Response:
    form = dict(await request.form())
    if not await _verify_csrf(request, form):
        return HTMLResponse(
            templates.render_error("Invalid or expired form submission. Please retry."),
            status_code=400,
        )

    flow_id = str(form.get("flow_id", ""))
    flow = _pending_flows.get(flow_id)
    oauth_params = _oauth_params_from_mapping(form)
    if flow is None:
        return HTMLResponse(
            templates.render_error("This login attempt has expired. Please start again."),
            status_code=400,
        )

    client: TelegramClient = flow["client"]
    code = str(form.get("code", "")).strip()
    csrf_token, new_cookie = _csrf_state(request)

    try:
        await client.sign_in(flow["phone"], code)
    except errors.SessionPasswordNeededError:
        response = HTMLResponse(templates.render_password_form(oauth_params, flow_id, csrf_token))
        _apply_csrf_cookie(response, new_cookie)
        return response
    except (errors.PhoneCodeInvalidError, errors.PhoneCodeExpiredError) as exc:
        response = HTMLResponse(
            templates.render_code_form(oauth_params, flow_id, csrf_token, error=str(exc)),
            status_code=400,
        )
        _apply_csrf_cookie(response, new_cookie)
        return response

    _pending_flows.pop(flow_id, None)
    return await _finalize_login(
        client=client, api_id=flow["api_id"], api_hash=flow["api_hash"], oauth_params=oauth_params
    )


@mcp.custom_route("/telegram-login/password", methods=["POST"])
async def telegram_login_password(request: Request) -> Response:
    form = dict(await request.form())
    if not await _verify_csrf(request, form):
        return HTMLResponse(
            templates.render_error("Invalid or expired form submission. Please retry."),
            status_code=400,
        )

    flow_id = str(form.get("flow_id", ""))
    flow = _pending_flows.get(flow_id)
    oauth_params = _oauth_params_from_mapping(form)
    if flow is None:
        return HTMLResponse(
            templates.render_error("This login attempt has expired. Please start again."),
            status_code=400,
        )

    client: TelegramClient = flow["client"]
    password = str(form.get("password", ""))
    csrf_token, new_cookie = _csrf_state(request)

    try:
        await client.sign_in(password=password)
    except errors.PasswordHashInvalidError:
        response = HTMLResponse(
            templates.render_password_form(
                oauth_params, flow_id, csrf_token, error="Incorrect password."
            ),
            status_code=400,
        )
        _apply_csrf_cookie(response, new_cookie)
        return response

    _pending_flows.pop(flow_id, None)
    return await _finalize_login(
        client=client, api_id=flow["api_id"], api_hash=flow["api_hash"], oauth_params=oauth_params
    )


@mcp.custom_route("/telegram-login/consent", methods=["POST"])
async def telegram_login_consent(request: Request) -> Response:
    form = dict(await request.form())
    if not await _verify_csrf(request, form):
        return HTMLResponse(
            templates.render_error("Invalid or expired form submission. Please retry."),
            status_code=400,
        )

    oauth_params = _oauth_params_from_mapping(form)
    telegram_user_id = _telegram_user_id_from_browser_session(request)
    if telegram_user_id is None:
        return HTMLResponse(
            templates.render_error("Your session has expired. Please start again."),
            status_code=400,
        )

    redirect_url = oauth_provider.issue_authorization_code(
        telegram_user_id=telegram_user_id,
        client_id=oauth_params["client_id"],
        redirect_uri=oauth_params["redirect_uri"],
        state=oauth_params.get("state"),
        scopes=oauth_params["scope"].split() if oauth_params.get("scope") else [],
        code_challenge=oauth_params["code_challenge"],
        redirect_uri_provided_explicitly=oauth_params.get("redirect_uri_provided_explicitly")
        == "1",
        resource=oauth_params.get("resource"),
    )
    return RedirectResponse(redirect_url, status_code=302)
