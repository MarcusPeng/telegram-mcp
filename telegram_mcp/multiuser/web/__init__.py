"""Browser-facing routes for HTTP multi-user mode (Telegram login + consent).

Importing this package registers the @mcp.custom_route() handlers as a
side effect -- see telegram_login.py.
"""

from telegram_mcp.multiuser.web import telegram_login  # noqa: F401
