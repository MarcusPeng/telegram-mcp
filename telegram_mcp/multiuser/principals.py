"""Storage for linked Telegram principals.

One row = one specific Telegram login = one OAuth identity. There is no
separate username/password account layer: a principal is created the moment
a user completes Telegram's own QR or phone+code(+2FA) login with their own
api_id/api_hash (see web/telegram_login.py). Re-linking the same Telegram
account later updates this row in place (upsert keyed by telegram_user_id)
rather than creating a duplicate identity.
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Optional

from telegram_mcp.multiuser import crypto


@dataclass
class Principal:
    telegram_user_id: int
    api_id: int
    api_hash: str
    session_string: str
    phone: Optional[str]


def upsert_principal(
    conn: sqlite3.Connection,
    *,
    telegram_user_id: int,
    api_id: int,
    api_hash: str,
    session_string: str,
    phone: Optional[str],
) -> None:
    now = int(time.time())
    api_id_enc = crypto.encrypt_field(
        str(api_id), telegram_user_id=telegram_user_id, field="api_id"
    )
    api_hash_enc = crypto.encrypt_field(
        api_hash, telegram_user_id=telegram_user_id, field="api_hash"
    )
    session_enc = crypto.encrypt_field(
        session_string, telegram_user_id=telegram_user_id, field="session"
    )
    conn.execute(
        """
        INSERT INTO telegram_principals
            (telegram_user_id, api_id_enc, api_hash_enc, session_enc, phone,
             created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(telegram_user_id) DO UPDATE SET
            api_id_enc = excluded.api_id_enc,
            api_hash_enc = excluded.api_hash_enc,
            session_enc = excluded.session_enc,
            phone = excluded.phone,
            updated_at = excluded.updated_at
        """,
        (telegram_user_id, api_id_enc, api_hash_enc, session_enc, phone, now, now),
    )
    conn.commit()


def get_principal(conn: sqlite3.Connection, telegram_user_id: int) -> Optional[Principal]:
    row = conn.execute(
        "SELECT api_id_enc, api_hash_enc, session_enc, phone "
        "FROM telegram_principals WHERE telegram_user_id = ?",
        (telegram_user_id,),
    ).fetchone()
    if row is None:
        return None
    api_id = int(
        crypto.decrypt_field(row["api_id_enc"], telegram_user_id=telegram_user_id, field="api_id")
    )
    api_hash = crypto.decrypt_field(
        row["api_hash_enc"], telegram_user_id=telegram_user_id, field="api_hash"
    )
    session_string = crypto.decrypt_field(
        row["session_enc"], telegram_user_id=telegram_user_id, field="session"
    )
    return Principal(
        telegram_user_id=telegram_user_id,
        api_id=api_id,
        api_hash=api_hash,
        session_string=session_string,
        phone=row["phone"],
    )


def principal_exists(conn: sqlite3.Connection, telegram_user_id: int) -> bool:
    row = conn.execute(
        "SELECT 1 FROM telegram_principals WHERE telegram_user_id = ?",
        (telegram_user_id,),
    ).fetchone()
    return row is not None
