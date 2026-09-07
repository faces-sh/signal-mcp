"""Reads served straight from Signal Desktop's own database.

WHY THIS EXISTS. This server used to answer every read from `store.py`, a private SQLite copy filled by
a manual import. Two things are wrong with a copy, and the second one is not obvious:

  1. It is only as fresh as the last time somebody pressed a button.
  2. It loses a message's conversation. `desktop._read_messages_from_plain_db` builds an outgoing
     message with `sender = own_number` and never sets `recipient`, and `store.list_conversations`
     groups by `CASE WHEN sender = own THEN recipient ELSE sender END`, so an outgoing direct message
     has no conversation at all and is dropped from every per-person read.

Measured on a live account: 827 of the user's own direct messages sat in the copy with no recipient and
no group. A conversation with one contact held 76 messages in Signal Desktop, 36 in and 39 out, and read
back as 7, all inbound. Anything built from that (a corpus of somebody's writing, most of all) gets one
side of a conversation and no sign that the other side ever existed.

Signal Desktop keeps `conversationId` on every row, in and out alike, so reading it directly fixes both
problems at once and deletes a whole copy of the user's history.

The database is SQLCipher encrypted with a key in the login Keychain, so a read decrypts to a temporary
plaintext file. That is expensive (tens of MB), so the copy is cached and reused until Signal Desktop
writes to the original again. WRITES STILL GO THROUGH signal-cli: this module never opens the real file
for anything but reading, and never writes to Signal Desktop at all.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from . import desktop
from .models import Message

log = logging.getLogger(__name__)

# The decrypted copy, and what the original looked like when it was made. Signal Desktop is a live
# application, so the answer to "is this stale" is the source file's own mtime and size, never a timer.
_lock = threading.Lock()
_cached: tuple[tuple[int, int], Path] | None = None


# WHAT COUNTS AS A MESSAGE, in ONE place and in SQL rather than in Python.
#
# Signal Desktop keeps call history, empty rows and tombstones in the same table as writing. Deciding
# that after the query looked harmless and was not: `LIMIT 50` counted rows that were then thrown away,
# so a caller asking for fifty messages could be handed one, and `list_conversations` reported counts
# that included things nobody wrote. Anything that filters must filter the same way, so it is written
# once here and every query says WHERE {IS_WRITING}.
IS_WRITING = ("type IN ('incoming', 'outgoing') "
              "AND (hasAttachments = 1 OR (body IS NOT NULL AND TRIM(body) != ''))")


def available() -> bool:
    """Whether Signal Desktop is installed and has a database to read."""
    try:
        return desktop.SIGNAL_DB.exists() and desktop.SIGNAL_CONFIG.exists()
    except OSError:
        return False


def _fingerprint() -> tuple[int, int]:
    stat = desktop.SIGNAL_DB.stat()
    return (stat.st_mtime_ns, stat.st_size)


def _plain_db() -> Path:
    """A readable copy of Signal Desktop's database, decrypting only when it has changed.

    Decrypting is the expensive part of every read, and a single turn can easily make several (look the
    person up, then read the conversation, then export it). Keyed on the source's mtime and size so a
    burst costs one decryption and a genuinely new message costs another.
    """
    global _cached
    with _lock:
        now = _fingerprint()
        if _cached is not None:
            seen, path = _cached
            if seen == now and path.exists():
                return path
            path.unlink(missing_ok=True)
            _cached = None
        config = json.loads(desktop.SIGNAL_CONFIG.read_text())
        key = desktop._get_db_key_hex(config["encryptedKey"])
        path = desktop._decrypt_db_to_temp(key, desktop.SIGNAL_DB)
        _cached = (now, path)
        return path


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_plain_db()))
    conn.row_factory = sqlite3.Row
    return conn


def _identifiers(row: sqlite3.Row) -> list[str]:
    """Every way this conversation can be named, so a caller's handle matches whichever it holds.

    A conversation is asked for by phone number, by service id, or by group id depending on which part of
    the system is asking, and none of them is more correct than the others.
    """
    keys = [row["e164"], row["serviceId"], _group_id(row), row["id"]]
    return [k for k in keys if k]


def _group_id(row: sqlite3.Row) -> str | None:
    raw = row["groupId"]
    if not raw:
        return None
    return desktop._decode_group_id(raw) if hasattr(desktop, "_decode_group_id") else raw


def _display_name(row: sqlite3.Row) -> str:
    for key in ("name", "profileFullName", "profileName", "e164"):
        value = row[key] if key in row.keys() else None
        if value and str(value).strip():
            return str(value).strip()
    return row["id"]


def _conversation_for(handle: str) -> sqlite3.Row | None:
    """The conversation a handle names, whatever kind of handle it is."""
    wanted = (handle or "").strip().lower()
    if not wanted:
        return None
    with _connect() as conn:
        for row in conn.execute("SELECT * FROM conversations"):
            if any(str(k).lower() == wanted for k in _identifiers(row)):
                return row
    return None


def _own_number(fallback: str = "") -> str:
    return fallback or ""


def _to_message(row: sqlite3.Row, conv: sqlite3.Row, own_number: str) -> Message | None:
    """One Desktop row as this server's Message, with BOTH ends of it filled in.

    The whole point: an outgoing message records who it went to. Without that a conversation read can
    only ever return the half somebody else wrote.
    """
    when = row["sent_at"] or row["received_at"] or 0
    if not when:
        return None
    body = row["body"] or ""
    if not body.strip() and not row["hasAttachments"]:
        return None

    group = _group_id(conv)
    other = conv["e164"] or conv["serviceId"] or conv["id"]
    outgoing = row["type"] == "outgoing"
    if outgoing:
        sender = own_number or "me"
        recipient = None if group else other
    else:
        sender = row["source"] or other
        recipient = None if group else (own_number or None)

    read_status = row["readStatus"] if "readStatus" in row.keys() else None
    return Message(
        id=f"desktop_{row['id']}",
        sender=sender,
        recipient=recipient,
        body=body,
        timestamp=datetime.fromtimestamp(when / 1000),
        group_id=group,
        is_read=(read_status == 0 if read_status is not None else True),
    )


def get_conversation(
    recipient: str, limit: int = 50, offset: int = 0, since: datetime | None = None,
    own_number: str = "",
) -> list[Message]:
    """Message history with one contact or group, oldest last, both sides of it."""
    conv = _conversation_for(recipient)
    if conv is None:
        return []
    clauses = ["conversationId = ?", IS_WRITING]
    params: list = [conv["id"]]
    if since:
        clauses.append("COALESCE(sent_at, received_at, 0) >= ?")
        params.append(int(since.timestamp() * 1000))
    params.extend([limit, offset])
    with _connect() as conn:
        rows = conn.execute(
            f"""SELECT * FROM messages WHERE {' AND '.join(clauses)}
                ORDER BY COALESCE(sent_at, received_at, 0) DESC LIMIT ? OFFSET ?""",
            params,
        ).fetchall()
    out = [_to_message(r, conv, own_number) for r in reversed(rows)]
    return [m for m in out if m]


def search_messages(
    query: str, limit: int = 50, offset: int = 0, sender: str | None = None, own_number: str = "",
) -> list[Message]:
    """Messages whose body matches, across every conversation."""
    wanted = (query or "").strip()
    if not wanted:
        return []
    with _connect() as conn:
        convs = {row["id"]: row for row in conn.execute("SELECT * FROM conversations")}
        rows = conn.execute(
            f"""SELECT * FROM messages
                WHERE {IS_WRITING} AND body LIKE ? ESCAPE '\\'
                ORDER BY COALESCE(sent_at, received_at, 0) DESC LIMIT ? OFFSET ?""",
            (f"%{wanted.replace(chr(92), chr(92) * 2).replace('%', chr(92) + '%')}%", limit, offset),
        ).fetchall()
    out = []
    for row in rows:
        conv = convs.get(row["conversationId"])
        if conv is None:
            continue
        message = _to_message(row, conv, own_number)
        if message and (not sender or message.sender == sender):
            out.append(message)
    return out


def list_conversations(own_number: str = "") -> list[dict]:
    """Every conversation that has messages, busiest first, in the shape the server already returns."""
    with _connect() as conn:
        counts = {
            row["conversationId"]: (row["n"], row["last"])
            for row in conn.execute(
                f"""SELECT conversationId, COUNT(*) AS n,
                           MAX(COALESCE(sent_at, received_at, 0)) AS last
                    FROM messages WHERE {IS_WRITING} GROUP BY conversationId"""
            )
        }
        rows = list(conn.execute("SELECT * FROM conversations"))
    out = []
    for row in rows:
        count, last = counts.get(row["id"], (0, 0))
        if not count:
            continue
        group = _group_id(row)
        out.append({
            "id": group or row["e164"] or row["serviceId"] or row["id"],
            "name": _display_name(row),
            "type": "group" if group else "direct",
            "message_count": count,
            "last_message_at": datetime.fromtimestamp(last / 1000).isoformat() if last else None,
        })
    out.sort(key=lambda c: c["last_message_at"] or "", reverse=True)
    return out


def list_contacts() -> list[dict]:
    """The people Signal Desktop knows, for resolving a name to something a read can use."""
    with _connect() as conn:
        rows = list(conn.execute("SELECT * FROM conversations WHERE type = 'private'"))
    return [{
        "number": row["e164"],
        "uuid": row["serviceId"],
        "name": _display_name(row),
        "display_name": _display_name(row),
        "profile_name": row["profileName"],
    } for row in rows if row["e164"] or row["serviceId"]]
