"""HTTP multi-user mode: OAuth authorization server + per-user Telegram linking.

Only imported when TELEGRAM_MCP_TRANSPORT=http. stdio mode never touches this
package, so its dependencies (cryptography, pyjwt) and SQLite storage stay
out of the default single-user/Claude-Desktop code path entirely.
"""
