"""AuthSettings + public-URL configuration for HTTP multi-user mode."""

import os

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions

REQUIRED_SCOPE = "telegram"


def public_url() -> str:
    url = os.getenv("TELEGRAM_MCP_PUBLIC_URL")
    if not url:
        raise SystemExit(
            "TELEGRAM_MCP_PUBLIC_URL is required when TELEGRAM_MCP_TRANSPORT=http "
            "(the public base URL MCP clients use to reach this server, e.g. "
            "https://telegram-mcp.example.com)."
        )
    return url.rstrip("/")


def build_auth_settings() -> AuthSettings:
    base_url = public_url()
    return AuthSettings(
        issuer_url=base_url,
        resource_server_url=base_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[REQUIRED_SCOPE],
            default_scopes=[REQUIRED_SCOPE],
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=[REQUIRED_SCOPE],
    )
