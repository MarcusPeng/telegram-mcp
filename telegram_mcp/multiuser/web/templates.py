"""Minimal HTML rendering for the Telegram-login web flow.

Plain f-strings rather than Jinja2 -- this is ~6 small, static-shaped pages,
not enough surface area to justify a templating-engine dependency. Every
value that isn't a hardcoded literal is passed through html.escape().
"""

import html
from typing import Dict, Optional
from urllib.parse import urlencode


def _hidden_fields(oauth_params: Dict[str, str]) -> str:
    return "\n".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
        for k, v in oauth_params.items()
    )


def _page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 480px; margin: 48px auto; padding: 0 16px; }}
label {{ display: block; margin-top: 12px; }}
input[type=text], input[type=password] {{ width: 100%; padding: 8px; margin-top: 4px; box-sizing: border-box; }}
button {{ margin-top: 16px; padding: 10px 16px; }}
.error {{ color: #b00020; }}
img.qr {{ display: block; margin: 16px auto; }}
</style>
</head>
<body>
<h2>{html.escape(title)}</h2>
{body}
</body>
</html>"""


def render_error(message: str) -> str:
    return _page("Error", f'<p class="error">{html.escape(message)}</p>')


def render_connect_page(
    oauth_params: Dict[str, str], csrf_token: str, error: Optional[str] = None
) -> str:
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    body = f"""
<p>Connect your Telegram account to authorize this app. You'll need your own
api_id/api_hash from
<a href="https://my.telegram.org/apps" target="_blank">my.telegram.org/apps</a>.</p>
{error_html}
<form method="post" action="/telegram-login/start">
{_hidden_fields(oauth_params)}
<input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}">
<label>API ID <input type="text" name="api_id" required></label>
<label>API Hash <input type="text" name="api_hash" required></label>
<label><input type="radio" name="method" value="qr" checked> QR code login</label>
<label><input type="radio" name="method" value="phone"> Phone number login</label>
<label>Phone number (only needed for phone login)
<input type="text" name="phone" placeholder="+15551234567"></label>
<button type="submit">Continue</button>
</form>
"""
    return _page("Connect your Telegram account", body)


def render_qr_page(qr_url: str, qr_data_uri: str, flow_id: str, refresh_seconds: int = 3) -> str:
    poll_url = f"/telegram-login/qr-status?flow_id={html.escape(flow_id)}"
    body = f"""
<meta http-equiv="refresh" content="{refresh_seconds};url={poll_url}">
<p>Scan this QR code with Telegram: Settings &gt; Devices &gt; Link Desktop Device.</p>
<img class="qr" src="{qr_data_uri}" alt="QR code">
<p>Or open on a device where you're already logged in:<br>
<a href="{html.escape(qr_url)}">{html.escape(qr_url)}</a></p>
<p>This page refreshes automatically while waiting for you to scan.</p>
"""
    return _page("Scan to connect Telegram", body)


def render_code_form(
    oauth_params: Dict[str, str], flow_id: str, csrf_token: str, error: Optional[str] = None
) -> str:
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    body = f"""
{error_html}
<form method="post" action="/telegram-login/code">
{_hidden_fields(oauth_params)}
<input type="hidden" name="flow_id" value="{html.escape(flow_id)}">
<input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}">
<label>Code sent to your Telegram app <input type="text" name="code" required autofocus></label>
<button type="submit">Continue</button>
</form>
"""
    return _page("Enter the code", body)


def render_password_form(
    oauth_params: Dict[str, str], flow_id: str, csrf_token: str, error: Optional[str] = None
) -> str:
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    body = f"""
{error_html}
<p>Two-factor authentication is enabled on this account.</p>
<form method="post" action="/telegram-login/password">
{_hidden_fields(oauth_params)}
<input type="hidden" name="flow_id" value="{html.escape(flow_id)}">
<input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}">
<label>Password <input type="password" name="password" required autofocus></label>
<button type="submit">Continue</button>
</form>
"""
    return _page("Two-factor authentication", body)


def render_consent_page(
    oauth_params: Dict[str, str],
    csrf_token: str,
    phone: Optional[str],
    client_name: Optional[str],
) -> str:
    who = html.escape(phone or "your linked Telegram account")
    app_name = html.escape(client_name or "This application")
    relogin_qs = html.escape(urlencode({**oauth_params, "force_relogin": "1"}))
    body = f"""
<p>{app_name} wants to access Telegram via <strong>{who}</strong>.</p>
<form method="post" action="/telegram-login/consent">
{_hidden_fields(oauth_params)}
<input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}">
<button type="submit">Authorize</button>
</form>
<p><a href="/telegram-login?{relogin_qs}">Use a different Telegram account</a></p>
"""
    return _page("Authorize access", body)
