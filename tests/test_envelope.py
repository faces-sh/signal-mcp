"""The uniform failure envelope, end to end (docs/MCP_FAILURE_ENVELOPE.md).

Three representative failures a person actually hits, each driven through the real
tool handler rather than asserted on a helper: signal-cli not installed, the Signal
Desktop database refusing to decrypt, and a send to a number that is not on Signal.
Plus the shape rules themselves: isError, the leading code, the verbatim body, the
absent HTTP line, redaction and truncation.
"""

import sqlite3
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

import signal_mcp.store as _store_mod
from signal_mcp import envelope
from signal_mcp.client import SignalClient
from signal_mcp.config import DAEMON_URL
from signal_mcp.server import call_tool
from tests.envelope_helpers import failure


@pytest.fixture(autouse=True)
def reset_client(monkeypatch, tmp_path):
    monkeypatch.setattr(_store_mod, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(_store_mod, "_initialized_paths", set())
    if getattr(_store_mod._thread_local, "conn", None) is not None:
        _store_mod._thread_local.conn.close()
        _store_mod._thread_local.conn = None
    test_client = SignalClient(account="+10000000000")
    monkeypatch.setattr("signal_mcp.server._client", test_client)
    return test_client


# ── 1. signal-cli is not installed ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_signal_cli_missing_returns_not_installed(reset_client, monkeypatch):
    """No signal-cli on PATH: [not_installed], the OSError verbatim, no HTTP line."""
    monkeypatch.setattr("signal_mcp.client._daemon_last_ok_at", 0.0)
    monkeypatch.setattr(reset_client, "_daemon_alive", _false)
    monkeypatch.setattr("signal_mcp.client.read_daemon_pid", lambda: None)
    monkeypatch.setattr("signal_mcp.client.save_daemon_pid", lambda pid: None)

    boom = FileNotFoundError(2, "No such file or directory: 'signal-cli'")
    with patch("signal_mcp.client.subprocess.Popen", side_effect=boom):
        result = await call_tool("send_message",
                                 {"recipient": "+12025551234", "message": "hi"})

    code, text = failure(result)
    assert code == "not_installed"
    lines = text.splitlines()
    assert lines[0] == ("[not_installed] Could not send the message: "
                        "signal-cli is not installed or not on PATH.")
    # Rule 4: nothing here was HTTP, so no status line was invented.
    assert not any(line.startswith("HTTP ") for line in lines)
    # Rule 5: the OS's own words, untouched.
    assert "No such file or directory: 'signal-cli'" in text


# ── 2. the Signal Desktop database will not decrypt ───────────────────────────

@pytest.mark.asyncio
async def test_db_decrypt_failure_returns_envelope_with_key_redacted(tmp_path):
    """sqlcipher refuses the key: [db_decrypt_failed], its stderr verbatim, key redacted."""
    signal_dir = tmp_path / "Signal"
    (signal_dir / "sql").mkdir(parents=True)
    (signal_dir / "sql" / "db.sqlite").write_bytes(b"encrypted")
    (signal_dir / "config.json").write_text('{"encryptedKey": "aabb"}')

    db_key = "de" * 32
    # sqlcipher echoes the offending script line, which holds the raw database key.
    sqlcipher_result = MagicMock()
    sqlcipher_result.returncode = 1
    sqlcipher_result.stdout = ""
    sqlcipher_result.stderr = (
        f'Error: near line 1: PRAGMA key = "x\'{db_key}\'";\n'
        "Error: file is not a database"
    )

    with patch("signal_mcp.desktop.SIGNAL_DB", signal_dir / "sql" / "db.sqlite"), \
         patch("signal_mcp.desktop.SIGNAL_CONFIG", signal_dir / "config.json"), \
         patch("signal_mcp.desktop._get_db_key_hex", return_value=db_key), \
         patch("signal_mcp.desktop._find_sqlcipher", return_value="/usr/bin/sqlcipher"), \
         patch("signal_mcp.desktop.subprocess.run", return_value=sqlcipher_result):
        result = await call_tool("import_desktop", {})

    code, text = failure(result)
    assert code == "db_decrypt_failed"
    assert text.splitlines()[0].startswith(
        "[db_decrypt_failed] Could not import your Signal Desktop history:")
    # Rule 5: sqlcipher's diagnosis survives, because only the caller can act on it.
    assert "Error: file is not a database" in text
    # Rule 8: the database key does not.
    assert db_key not in text
    assert "<redacted>" in text


# ── 3. sending to a number that is not on Signal ──────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_send_to_unregistered_recipient_returns_no_such_recipient():
    """signal-cli refuses the recipient: [no_such_recipient], its JSON verbatim."""
    respx.post(DAEMON_URL).mock(return_value=httpx.Response(200, json={
        "jsonrpc": "2.0", "id": 1,
        "error": {
            "code": -1,
            "message": "Failed to send message",
            "data": {"response": {"results": [{
                "recipientAddress": {"number": "+12025550000"},
                "type": "UNREGISTERED_FAILURE",
            }]}},
        },
    }))
    result = await call_tool("send_message",
                             {"recipient": "+12025550000", "message": "hi"})

    code, text = failure(result)
    assert code == "no_such_recipient"
    assert text.splitlines()[0] == (
        "[no_such_recipient] Could not send the message: "
        "signal-cli reported an error for 'send'.")
    assert "UNREGISTERED_FAILURE" in text
    assert "+12025550000" in text          # the number is the answer, not a secret


@respx.mock
@pytest.mark.asyncio
async def test_send_refused_in_a_200_is_not_reported_as_sent():
    """A 200 carrying a refusal is a failure, never {"status": "sent"} (rule 6)."""
    respx.post(DAEMON_URL).mock(return_value=httpx.Response(200, json={
        "jsonrpc": "2.0", "id": 1,
        "result": {"timestamp": 1700000000000, "results": [{
            "recipientAddress": {"number": "+12025550000"},
            "type": "UNREGISTERED_FAILURE",
        }]},
    }))
    result = await call_tool("send_message",
                             {"recipient": "+12025550000", "message": "hi"})

    code, text = failure(result)
    assert code == "no_such_recipient"
    assert "sent" not in text
    # and nothing was written to the local store as though it had gone out
    assert _store_mod.get_conversation("+12025550000") == []


# ── the question that was asked is the question that gets answered ────────────

@pytest.mark.asyncio
async def test_unknown_tool_says_so_even_with_no_signal_cli(reset_client, monkeypatch):
    """"There is no such tool" must not come back as "the daemon would not start"."""
    monkeypatch.setattr("signal_mcp.client._daemon_last_ok_at", 0.0)
    monkeypatch.setattr(reset_client, "_daemon_alive", _false)
    with patch("signal_mcp.client.subprocess.Popen",
               side_effect=FileNotFoundError(2, "No such file or directory")):
        result = await call_tool("nonexistent_tool", {})
    assert failure(result)[0] == "unknown_tool"


@pytest.mark.asyncio
async def test_missing_argument_says_so_even_with_no_signal_cli(reset_client, monkeypatch):
    """A malformed request is answered without first trying to start a daemon."""
    monkeypatch.setattr("signal_mcp.client._daemon_last_ok_at", 0.0)
    monkeypatch.setattr(reset_client, "_daemon_alive", _false)
    with patch("signal_mcp.client.subprocess.Popen",
               side_effect=FileNotFoundError(2, "No such file or directory")) as popen:
        result = await call_tool("send_message", {"recipient": "+12025551234"})
    code, text = failure(result)
    assert code == "bad_request"
    assert "message" in text
    popen.assert_not_called()


# ── the shape rules ───────────────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_http_failure_carries_a_literal_status_line():
    """The one HTTP failure here gets http_<status> and the literal status line."""
    respx.post(DAEMON_URL).mock(return_value=httpx.Response(503, text="upstream is down"))
    result = await call_tool("list_groups", {})

    code, text = failure(result)
    assert code == "http_503"
    lines = text.splitlines()
    assert lines[1] == "HTTP 503 Service Unavailable"
    assert lines[2] == "upstream is down"


def test_render_omits_the_status_line_when_there_was_no_http():
    text = envelope.render("not_linked", "Could not send the message: no account.",
                           body="No accounts configured.")
    assert text == ("[not_linked] Could not send the message: no account.\n"
                    "No accounts configured.")


def test_render_truncates_a_long_body_and_says_so():
    text = envelope.render("signal_cli_failed", "Could not send the message: it failed.",
                           body="x" * (envelope.MAX_BODY + 500))
    assert text.endswith(" ...[truncated]")
    assert len(text) < envelope.MAX_BODY + 200


@pytest.mark.parametrize("raw, gone", [
    ('{"access_token": "ya29.SECRETVALUE"}', "ya29.SECRETVALUE"),
    ('{"profileKey": "Zm9vYmFyYmF6"}', "Zm9vYmFyYmF6"),
    ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
    ("Cookie: session=deadbeef", "session=deadbeef"),
    ("registration_lock = 123456", "123456"),
    ("PRAGMA key = \"x'" + "ab" * 32 + "'\";", "ab" * 32),
    ("identity key: " + "cd" * 32, "cd" * 32),
])
def test_redaction_removes_credentials(raw, gone):
    out = envelope.redact(raw)
    assert gone not in out
    assert "<redacted>" in out


def test_redaction_leaves_phone_numbers_and_prose_alone():
    raw = "Failed to send to +12025550000: recipient is not registered"
    assert envelope.redact(raw) == raw


def test_sqlite_code_reads_sqlites_own_result_code():
    """A locked store and a missing store are different answers, so they get different codes."""
    busy = sqlite3.OperationalError("database is locked")
    busy.sqlite_errorname = "SQLITE_BUSY"
    assert envelope.sqlite_code(busy) == "db_locked"

    cantopen = sqlite3.OperationalError("unable to open database file")
    cantopen.sqlite_errorname = "SQLITE_CANTOPEN"
    assert envelope.sqlite_code(cantopen) == "db_missing"

    notadb = sqlite3.DatabaseError("file is not a database")
    notadb.sqlite_errorname = "SQLITE_NOTADB"
    assert envelope.sqlite_code(notadb) == "db_decrypt_failed"

    io_err = sqlite3.OperationalError("disk I/O error")
    io_err.sqlite_errorname = "SQLITE_IOERR_READ"   # extended code
    assert envelope.sqlite_code(io_err) == "db_io_error"

    assert envelope.sqlite_code(sqlite3.Error("who knows")) == "db_error"


@pytest.mark.asyncio
async def test_locked_store_is_not_answered_with_an_empty_conversation(monkeypatch):
    """"I could not read your history" must never come back as "no messages" (rule 6)."""
    locked = sqlite3.OperationalError("database is locked")
    locked.sqlite_errorname = "SQLITE_BUSY"

    def boom(*a, **kw):
        raise locked

    monkeypatch.setattr(_store_mod, "get_conversation", boom)
    result = await call_tool("get_conversation", {"recipient": "+12025551234"})

    code, text = failure(result)
    assert code == "db_locked"
    assert "database is locked" in text
    assert "[]" not in text


async def _false(*_a, **_kw):
    return False
