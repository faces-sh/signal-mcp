"""Signal Desktop database importer.

Reads ALL historical messages from Signal Desktop's local SQLCipher database
and imports them into the signal-mcp store.

Signal Desktop stores:
  macOS:   ~/Library/Application Support/Signal/
  Linux:   ~/.config/Signal/
  Windows: %APPDATA%/Signal/

  DB:  <dir>/sql/db.sqlite  (SQLCipher 4)
  Key: <dir>/config.json    (encryptedKey, Chromium v10)

The encryptedKey is AES-128-CBC encrypted with a password from the OS keychain:
  macOS:   Keychain service "Signal Safe Storage"
  Linux:   libsecret / GNOME Keyring ("Signal Safe Storage"), fallback "peanuts"
  Windows: DPAPI (not yet supported — use manual key)
"""

import json
import os
import platform
import subprocess
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding

from .envelope import ToolFailure, sqlite_code as _sqlite_code
from .models import Attachment, Message
from .config import detect_account
from . import store as _store


def _signal_dir() -> Path:
    """Return the Signal Desktop data directory for the current platform."""
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Signal"
    elif system == "Linux":
        return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "Signal"
    elif system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        return Path(appdata) / "Signal"
    # Fallback
    return Path.home() / ".config" / "Signal"


SIGNAL_DIR = _signal_dir()
SIGNAL_DB = SIGNAL_DIR / "sql" / "db.sqlite"
SIGNAL_CONFIG = SIGNAL_DIR / "config.json"


class DesktopImportError(ToolFailure):
    """Anything that stopped the Signal Desktop history import.

    Carries the envelope code plus whatever sqlcipher, SQLite or the OS keychain
    actually printed, unedited (rule 5).
    """

    def __init__(self, detail: str, code: str = "desktop_import_failed",
                 body: str | None = None, http: str | None = None):
        super().__init__(detail, code=code, body=body, http=http)


def _get_keychain_password() -> bytes:
    """Retrieve the Signal Safe Storage password from the OS keychain."""
    system = platform.system()

    if system == "Darwin":
        attempts: list[str] = []
        for service in ("Signal Safe Storage", "Signal Keys", "Electron Keys"):
            try:
                result = subprocess.run(
                    ["security", "find-generic-password", "-s", service, "-w"],
                    capture_output=True, text=True, timeout=30,
                )
            except FileNotFoundError as exc:
                raise DesktopImportError(
                    "the macOS security command is not available.",
                    code="not_installed",
                    body=f"{type(exc).__name__}: {exc}",
                ) from exc
            except subprocess.TimeoutExpired as exc:
                raise DesktopImportError(
                    "the macOS Keychain did not answer within 30 seconds.",
                    code="timeout",
                    body=f"{type(exc).__name__}: {exc}",
                ) from exc
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().encode()
            # Keep what security said about each service; it is the only evidence
            # of whether the item is absent or access was denied.
            attempts.append(f"security -s {service!r} exited {result.returncode}: "
                            f"{result.stderr.strip()}")
        raise DesktopImportError(
            "the Signal Desktop password is not readable from the macOS Keychain.",
            code="keychain_unavailable",
            body="\n".join(attempts),
        )

    elif system == "Linux":
        # Try secret-tool (GNOME Keyring / libsecret)
        for label in ("Signal Safe Storage", "Electron Safe Storage"):
            try:
                result = subprocess.run(
                    ["secret-tool", "lookup", "application", "Signal"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip().encode()
            except FileNotFoundError:
                pass
            try:
                result = subprocess.run(
                    ["secret-tool", "lookup", "label", label],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip().encode()
            except FileNotFoundError:
                break
        # Signal Desktop on Linux falls back to hardcoded password when no keyring is available
        return b"peanuts"

    elif system == "Windows":
        # On Windows, Electron's safeStorage uses DPAPI to encrypt the key directly.
        # We call CryptUnprotectData via ctypes to decrypt — no PBKDF2 involved.
        # The decrypted bytes ARE the raw DB key (32 bytes → 64 hex chars).
        raise DesktopImportError(
            "Windows keys are read with DPAPI, not the keychain path.",
            code="unsupported_platform",
            body="_decrypt_dpapi_key() is the Windows entry point, not _get_keychain_password().",
        )

    else:
        raise DesktopImportError(
            f"this server cannot read the Signal Desktop key on {system}.",
            code="unsupported_platform",
        )


def _decrypt_dpapi_key(encrypted_hex: str) -> str:
    """Windows only: DPAPI-decrypt Signal Desktop's encryptedKey → raw DB key hex."""
    try:
        import ctypes
        import ctypes.wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char)),
            ]

        raw = bytes.fromhex(encrypted_hex)
        # Strip known Electron prefixes (v10, v11) if present
        for prefix in (b"v10", b"v11"):
            if raw.startswith(prefix):
                raw = raw[len(prefix):]
                break

        p = ctypes.create_string_buffer(raw, len(raw))
        blobin = DATA_BLOB(len(raw), p)
        blobout = DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout)
        )
        if not ok:
            raise DesktopImportError(
                "Windows DPAPI refused to decrypt the Signal Desktop key.",
                code="db_decrypt_failed",
                body=f"CryptUnprotectData returned {ok!r}",
            )
        result = ctypes.string_at(blobout.pbData, blobout.cbData)
        ctypes.windll.kernel32.LocalFree(blobout.pbData)
        return result.hex()
    except DesktopImportError:
        raise
    except Exception as exc:
        raise DesktopImportError(
            "the Signal Desktop key could not be decrypted on Windows.",
            code="db_decrypt_failed",
            body=f"{type(exc).__name__}: {exc}",
        ) from exc


def _get_db_key_hex(encrypted_hex: str) -> str:
    """Return the raw SQLCipher DB key hex, handling all platforms."""
    if platform.system() == "Windows":
        return _decrypt_dpapi_key(encrypted_hex)
    password = _get_keychain_password()
    return _decrypt_key(encrypted_hex, password)


def _decrypt_key(encrypted_hex: str, password: bytes) -> str:
    """Decrypt Signal Desktop's encryptedKey (Chromium v10 AES-CBC format)."""
    raw = bytes.fromhex(encrypted_hex)
    if not raw.startswith(b"v10"):
        raise DesktopImportError(
            "the Signal Desktop key is stored in a format this server does not know.",
            code="db_decrypt_failed",
            body=f"encryptedKey prefix={raw[:3]!r}",
        )

    ciphertext = raw[3:]

    # Chromium key derivation: PBKDF2-SHA1, salt="saltysalt", 1003 iterations, 16 bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),  # noqa: S303  (Chromium's choice, not ours)
        length=16,
        salt=b"saltysalt",
        iterations=1003,
    )
    aes_key = kdf.derive(password)

    # Decrypt AES-128-CBC, IV = 0x20 * 16 (space character)
    iv = b"\x20" * 16
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    db_key_bytes = unpadder.update(plaintext) + unpadder.finalize()

    # Signal Desktop stores the SQLCipher key as a hex-encoded ASCII string
    # (e.g. b'3a0aaac0...'), not raw binary bytes.  Decode it directly instead
    # of calling .hex() which would double-encode and produce the wrong key.
    try:
        candidate = db_key_bytes.decode("ascii")
        if len(candidate) in (64, 128) and all(c in "0123456789abcdefABCDEF" for c in candidate):
            return candidate.lower()
    except (UnicodeDecodeError, ValueError):
        pass
    # Fallback for platforms that do store raw bytes: hex-encode them
    return db_key_bytes.hex()


def _decrypt_db_to_temp(db_key_hex: str, db_path: Path | None = None) -> Path:
    """Use sqlcipher CLI to export the encrypted DB to a plain SQLite file."""
    sqlcipher = _find_sqlcipher()
    source = db_path or SIGNAL_DB
    fd, tmp_str = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    tmp = Path(tmp_str)

    script = (
        f"PRAGMA key = \"x'{db_key_hex}'\";\n"
        f"PRAGMA cipher_page_size = 4096;\n"
        f"PRAGMA kdf_iter = 1;\n"
        f"PRAGMA cipher_hmac_algorithm = HMAC_SHA512;\n"
        f"PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;\n"
        f"ATTACH DATABASE '{tmp}' AS plaintext KEY '';\n"
        f"SELECT sqlcipher_export('plaintext');\n"
        f"DETACH DATABASE plaintext;\n"
        f".quit\n"
    )

    try:
        result = subprocess.run(
            [sqlcipher, str(source)],
            input=script, capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired as exc:
        tmp.unlink(missing_ok=True)
        raise DesktopImportError(
            "sqlcipher did not finish decrypting the Signal Desktop database within 60 seconds.",
            code="timeout",
            body=f"{type(exc).__name__}: {exc}",
        ) from exc
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        raise DesktopImportError(
            "sqlcipher could not be run.",
            code="not_installed",
            body=f"{type(exc).__name__}: {exc}",
        ) from exc

    # sqlcipher echoes the offending script line on a syntax error, and our script
    # holds the raw database key: the envelope redacts it on the way out (rule 8).
    if result.returncode != 0:
        tmp.unlink(missing_ok=True)
        raise DesktopImportError(
            f"sqlcipher exited with code {result.returncode} decrypting the "
            "Signal Desktop database.",
            code="db_decrypt_failed",
            body="\n".join(x for x in (result.stderr.strip(), result.stdout.strip()) if x),
        )
    if not tmp.exists() or tmp.stat().st_size == 0:
        tmp.unlink(missing_ok=True)
        raise DesktopImportError(
            "sqlcipher wrote nothing when decrypting the Signal Desktop database.",
            code="db_decrypt_failed",
            body="\n".join(x for x in (result.stderr.strip(), result.stdout.strip()) if x),
        )

    return tmp


def _find_sqlcipher() -> str:
    searched = ["/opt/homebrew/bin/sqlcipher", "/usr/local/bin/sqlcipher"]
    for path in searched:
        if Path(path).exists():
            return path
    result = subprocess.run(["which", "sqlcipher"], capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    raise DesktopImportError(
        "sqlcipher is not installed or not on PATH.",
        code="not_installed",
        body="Searched: " + ", ".join(searched) + f"\nwhich sqlcipher exited {result.returncode}",
    )


def _read_messages_from_plain_db(plain_db: Path, own_number: str = "", since_ms: int = 0) -> list[Message]:
    """Parse Signal Desktop's messages table into our Message model.

    since_ms: if > 0, only return messages with sent_at or received_at > since_ms.
    """
    try:
        conn = sqlite3.connect(str(plain_db))
    except sqlite3.Error as exc:
        raise DesktopImportError(
            "the decrypted Signal Desktop database could not be opened.",
            code=_sqlite_code(exc),
            body=f"{type(exc).__name__}: {exc}",
        ) from exc
    conn.row_factory = sqlite3.Row
    messages = []

    try:
        # Signal Desktop renamed sourceUuid → sourceServiceId in newer versions.
        # Detect whichever column is present and alias it to a stable name.
        msg_cols = {r[1] for r in conn.execute("PRAGMA table_info(messages)").fetchall()}
        if "sourceServiceId" in msg_cols:
            source_col = "m.sourceServiceId AS sourceUuid"
        elif "sourceUuid" in msg_cols:
            source_col = "m.sourceUuid AS sourceUuid"
        else:
            source_col = "NULL AS sourceUuid"

        # readStatus column present in Signal Desktop schema v39+
        # (renamed from "unread"). 1=read, 0=unread, NULL=unknown.
        if "readStatus" in msg_cols:
            read_col = "m.readStatus"
        else:
            read_col = "NULL AS readStatus"

        rows = conn.execute(
            f"""SELECT
                m.id,
                m.conversationId,
                m.type,
                m.body,
                m.sent_at,
                m.received_at,
                m.source,
                {source_col},
                m.hasAttachments,
                {read_col},
                c.e164    AS conv_e164,
                c.groupId AS conv_group_id
            FROM messages m
            LEFT JOIN conversations c ON c.id = m.conversationId
            WHERE m.type IN ('incoming', 'outgoing')
              AND (m.body IS NOT NULL OR m.hasAttachments = 1)
              AND COALESCE(m.sent_at, m.received_at, 0) > ?
            ORDER BY m.sent_at ASC""",
            (since_ms,),
        ).fetchall()

        for row in rows:
            ts_ms = row["sent_at"] or row["received_at"] or 0
            if not ts_ms:
                continue

            # Outgoing: source is NULL in Signal Desktop — use own account number
            if row["type"] == "outgoing":
                sender = own_number or "me"
            else:
                sender = row["source"] or row["sourceUuid"] or row["conv_e164"] or ""

            # Signal Desktop: readStatus=0 means read, 1=unread, NULL=unknown
            # Default unknown/old messages to read (safer than false unread counts)
            read_status = row["readStatus"]
            is_read = read_status == 0 if read_status is not None else True

            messages.append(Message(
                id=f"desktop_{row['id']}",
                sender=sender,
                body=row["body"] or "",
                timestamp=datetime.fromtimestamp(ts_ms / 1000),
                group_id=_decode_group_id(row["conv_group_id"]),
                is_read=is_read,
            ))
    except sqlite3.Error as exc:
        raise DesktopImportError(
            "the decrypted Signal Desktop database could not be read.",
            code=_sqlite_code(exc),
            body=f"{type(exc).__name__}: {exc}",
        ) from exc
    finally:
        conn.close()

    return messages


def _read_conversation_names(plain_db: Path) -> list[tuple[str, str, str]]:
    """Read (id, name, type) tuples from Signal Desktop's conversations table."""
    try:
        conn = sqlite3.connect(str(plain_db))
    except sqlite3.Error as exc:
        raise DesktopImportError(
            "the decrypted Signal Desktop database could not be opened.",
            code=_sqlite_code(exc),
            body=f"{type(exc).__name__}: {exc}",
        ) from exc
    conn.row_factory = sqlite3.Row
    try:
        conv_cols = {r[1] for r in conn.execute("PRAGMA table_info(conversations)").fetchall()}
        # profileName / profileFullName for DMs, name for groups
        name_expr_parts = []
        if "name" in conv_cols:
            name_expr_parts.append("c.name")
        if "profileFullName" in conv_cols:
            name_expr_parts.append("c.profileFullName")
        if "profileName" in conv_cols:
            name_expr_parts.append("c.profileName")
        if "e164" in conv_cols:
            name_expr_parts.append("c.e164")
        if not name_expr_parts:
            # No column we know how to read a name out of. That is a schema we cannot
            # handle, not a database with no names in it.
            raise DesktopImportError(
                "the Signal Desktop conversations table has no column this server "
                "can read a name from.",
                code="db_schema_unknown",
                body="Columns present: " + ", ".join(sorted(conv_cols)),
            )
        name_expr = f"COALESCE({', '.join(f'NULLIF({p}, \"\")' for p in name_expr_parts)})"

        rows = conn.execute(
            f"""SELECT
                c.id,
                c.type,
                c.groupId,
                c.e164,
                {name_expr} AS display_name
            FROM conversations c
            WHERE display_name IS NOT NULL AND display_name != ''"""
        ).fetchall()

        result = []
        for row in rows:
            conv_type = row["type"] or "private"
            group_id = _decode_group_id(row["groupId"])
            if conv_type == "group" and group_id:
                result.append((group_id, row["display_name"], "group"))
            elif row["e164"]:
                result.append((row["e164"], row["display_name"], "direct"))
        return result
    finally:
        conn.close()


def _decode_group_id(raw: str | None) -> str | None:
    """Signal Desktop stores group IDs as base64; convert to the format signal-cli uses."""
    if not raw:
        return None
    # Strip any Blob prefix Signal Desktop adds
    if raw.startswith("blob:") or len(raw) > 100:
        return None
    return raw


def import_from_desktop(progress_cb=None, signal_dir: Path | None = None, since_ms: int = 0) -> dict:
    """
    Full import pipeline: decrypt DB → parse → store.
    Returns {"imported": N, "skipped": N, "total": N, "platform": str, "source": str}.

    signal_dir: override the auto-detected Signal Desktop directory.
    since_ms: if > 0, only import messages newer than this epoch-millisecond timestamp.
    """
    if signal_dir is not None:
        # Explicit override — construct paths from it
        db_path = signal_dir / "sql" / "db.sqlite"
        config_path = signal_dir / "config.json"
    else:
        # Use module-level constants (patchable in tests, reflect current platform)
        db_path = SIGNAL_DB
        config_path = SIGNAL_CONFIG

    if not db_path.exists():
        raise DesktopImportError(
            "there is no Signal Desktop database on this machine.",
            code="db_missing",
            body=f"Looked for: {db_path}\nPlatform: {platform.system()}",
        )
    if not config_path.exists():
        raise DesktopImportError(
            "there is no Signal Desktop config on this machine.",
            code="config_missing",
            body=f"Looked for: {config_path}",
        )

    # 1. Read encrypted key from config
    try:
        config = json.loads(config_path.read_text())
    except (OSError, ValueError) as exc:
        raise DesktopImportError(
            "the Signal Desktop config could not be read.",
            code="config_unreadable",
            body=f"{config_path}: {type(exc).__name__}: {exc}",
        ) from exc
    encrypted_key_hex = config.get("encryptedKey")
    if not encrypted_key_hex:
        raise DesktopImportError(
            "the Signal Desktop config holds no database key.",
            code="config_unreadable",
            body=f"{config_path} has no encryptedKey field.",
        )

    if progress_cb:
        system = platform.system()
        if system == "Darwin":
            progress_cb("Unlocking macOS Keychain…")
        elif system == "Linux":
            progress_cb("Unlocking Linux keychain (GNOME Keyring / libsecret)…")
        else:
            progress_cb("Decrypting Signal Desktop key…")

    # 2. Derive the raw DB key (platform-specific)
    db_key_hex = _get_db_key_hex(encrypted_key_hex)

    if progress_cb:
        progress_cb("Decrypting Signal Desktop database…")

    # 3. Export encrypted DB to plain SQLite temp file
    plain_db = None
    try:
        plain_db = _decrypt_db_to_temp(db_key_hex, db_path)

        if progress_cb:
            progress_cb("Importing messages…")

        # 4. Parse messages: resolve own number for outgoing sender attribution.
        # Not optional: without it every outgoing message is stored under the sender
        # "me", which is wrong history written permanently into the local store.
        try:
            own_number = detect_account()
        except ToolFailure as exc:
            raise DesktopImportError(
                "your own Signal number could not be established, so imported messages "
                "would be filed under the wrong sender.",
                code=exc.code,
                body=exc.body,
            ) from exc
        messages = _read_messages_from_plain_db(plain_db, own_number=own_number, since_ms=since_ms)
        total = len(messages)
        imported = 0
        skipped = 0
        max_ts_ms = 0

        for i, msg in enumerate(messages):
            if _store.save_message(msg):
                imported += 1
            else:
                skipped += 1
            ts = int(msg.timestamp.timestamp() * 1000)
            if ts > max_ts_ms:
                max_ts_ms = ts
            if progress_cb and i % 500 == 0:
                progress_cb(f"  {i}/{total} messages…")

        # 5. Extract and store conversation names (groups + contacts).
        # The messages are already stored, so a failure here does not undo the import,
        # but it is reported in the result rather than disappearing.
        names_error = None
        try:
            conv_names = _read_conversation_names(plain_db)
            for conv_id, name, conv_type in conv_names:
                _store.save_conversation(conv_id, name, conv_type)
        except (sqlite3.Error, DesktopImportError) as exc:
            names_error = f"{type(exc).__name__}: {exc}"

        result = {
            "imported": imported,
            "skipped": skipped,
            "total": total,
            "max_ts_ms": max_ts_ms,
            "platform": platform.system(),
            "source": str(db_path.parent.parent),
        }
        if names_error:
            result["conversation_names_error"] = names_error
        return result
    finally:
        if plain_db is not None:
            plain_db.unlink(missing_ok=True)


def sync_from_desktop(progress_cb=None, signal_dir: Path | None = None) -> dict:
    """
    Incremental sync from Signal Desktop: imports only messages newer than the last sync.

    On the first call (no prior sync recorded) it imports everything — equivalent to
    import_from_desktop.  Subsequent calls are fast because they skip already-seen messages.
    Deduplication is handled atomically by INSERT OR IGNORE in the store, so messages
    already imported by import_from_desktop are silently skipped.

    Returns the import_from_desktop result dict plus:
      "since":       ISO datetime of the lower-bound filter (None on first run)
      "incremental": True if this was a delta sync, False if it was the first run
    """
    last_sync = _store.get_meta("desktop_last_sync")
    # Subtract a 60-second overlap so messages right at the boundary are never missed;
    # INSERT OR IGNORE deduplicates anything we've already stored.
    since_ms = max(0, int(last_sync) - 60_000) if last_sync else 0

    result = import_from_desktop(progress_cb=progress_cb, signal_dir=signal_dir, since_ms=since_ms)

    # Advance the watermark to the latest message timestamp seen (not wall-clock now).
    # Using wall-clock time caused messages to be lost whenever the Mac clock jumped
    # forward (sleep/wake, NTP, DST) — the watermark would leap past sent_at values.
    max_ts_ms = result.get("max_ts_ms", 0)
    if max_ts_ms > 0:
        new_mark = str(max_ts_ms)
        _store.set_meta("desktop_last_sync", new_mark)
    # If no messages were seen at all, leave the watermark unchanged so the next
    # sync re-scans from the same position rather than skipping forward.

    result["since"] = datetime.fromtimestamp(since_ms / 1000).isoformat() if since_ms else None
    result["incremental"] = last_sync is not None
    return result
