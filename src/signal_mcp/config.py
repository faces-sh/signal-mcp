"""Configuration: auto-detect Signal account, daemon URL, attachment dir."""

import json
import os
import re
import subprocess
from pathlib import Path

from .envelope import ToolFailure

DAEMON_PORT = 7583
DAEMON_URL = f"http://localhost:{DAEMON_PORT}/api/v1/rpc"
ATTACHMENT_DIR = Path.home() / "Downloads" / "signal-attachments"
DAEMON_PID_FILE = Path.home() / ".local" / "share" / "signal-mcp" / "daemon.pid"
DAEMON_MESSAGES_LOG = Path.home() / ".local" / "share" / "signal-mcp" / "daemon-messages.jsonl"
DAEMON_STDERR_LOG = Path.home() / ".local" / "share" / "signal-mcp" / "daemon.err"
RECEIVE_LOCK_FILE = Path.home() / ".local" / "share" / "signal-mcp" / "receive.lock"
WEBHOOK_CONFIG_FILE = Path.home() / ".local" / "share" / "signal-mcp" / "webhook.json"


class SignalCliUnavailable(ToolFailure, RuntimeError):
    """signal-cli is missing, unrunnable, or too old. Also a RuntimeError so serve() still catches it."""


class NotLinked(ToolFailure, RuntimeError):
    """signal-cli has no linked Signal account."""

# signal-cli stores account data here
_ACCOUNTS_JSON = Path.home() / ".local" / "share" / "signal-cli" / "data" / "accounts.json"

_account_cache: str | None = None


def detect_account() -> str:
    """Auto-detect linked Signal account number (cached).

    Reads accounts.json directly to avoid a slow signal-cli JVM cold-start.
    Falls back to `signal-cli listAccounts` if the file is missing.
    """
    global _account_cache
    if _account_cache is not None:
        return _account_cache

    # Fast path: parse accounts.json without spawning signal-cli
    accounts_json_error = ""
    if _ACCOUNTS_JSON.exists():
        try:
            data = json.loads(_ACCOUNTS_JSON.read_text())
            for acc in data.get("accounts", []):
                number = acc.get("number", "")
                if number.startswith("+"):
                    _account_cache = number
                    return _account_cache
        except Exception as exc:
            # Falling through to signal-cli is a real alternative route, not a swallow:
            # carry the parse failure so it lands in the envelope body if that route fails too.
            accounts_json_error = f"{_ACCOUNTS_JSON}: {type(exc).__name__}: {exc}\n"

    # Slow fallback: spawn signal-cli (takes ~15s on cold JVM start)
    try:
        result = subprocess.run(
            ["signal-cli", "listAccounts"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SignalCliUnavailable(
            "signal-cli is not installed or not on PATH.",
            code="not_installed",
            body=accounts_json_error + f"{type(exc).__name__}: {exc}",
        ) from exc
    if result.returncode != 0:
        raise SignalCliUnavailable(
            f"signal-cli listAccounts exited with code {result.returncode}.",
            code="signal_cli_failed",
            body=accounts_json_error + result.stderr.strip(),
        )

    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Number:"):
            _account_cache = line.split(":", 1)[1].strip()
            return _account_cache
        if line.startswith("+"):
            _account_cache = line.split()[0]
            return _account_cache

    raise NotLinked(
        "no Signal account is linked to signal-cli on this machine.",
        code="not_linked",
        body=accounts_json_error + result.stdout.strip(),
    )


MIN_SIGNAL_CLI_VERSION = (0, 13, 0)


def check_signal_cli_version() -> None:
    """Raise SignalCliUnavailable if signal-cli is missing, unrunnable, or too old."""
    try:
        result = subprocess.run(
            ["signal-cli", "--version"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError as exc:
        raise SignalCliUnavailable(
            "signal-cli is not installed or not on PATH.",
            code="not_installed",
            body=f"{type(exc).__name__}: {exc}",
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise SignalCliUnavailable(
            "signal-cli did not answer --version within 10 seconds.",
            code="timeout",
            body=f"{type(exc).__name__}: {exc}",
        ) from exc

    if result.returncode != 0:
        raise SignalCliUnavailable(
            f"signal-cli --version exited with code {result.returncode}.",
            code="signal_cli_failed",
            body=result.stderr.strip(),
        )

    match = re.search(r"(\d+)\.(\d+)\.(\d+)", result.stdout)
    if not match:
        raise SignalCliUnavailable(
            "signal-cli did not report a version number.",
            code="signal_cli_failed",
            body=result.stdout.strip(),
        )
    version = tuple(int(x) for x in match.groups())
    if version < MIN_SIGNAL_CLI_VERSION:
        min_str = ".".join(str(x) for x in MIN_SIGNAL_CLI_VERSION)
        raise SignalCliUnavailable(
            f"signal-cli {'.'.join(str(x) for x in version)} is older than the "
            f"minimum this server supports ({min_str}).",
            code="signal_cli_too_old",
            body=result.stdout.strip(),
        )


def ensure_attachment_dir() -> Path:
    ATTACHMENT_DIR.mkdir(parents=True, exist_ok=True)
    return ATTACHMENT_DIR


def save_daemon_pid(pid: int) -> None:
    DAEMON_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    DAEMON_PID_FILE.write_text(str(pid))


def read_daemon_pid() -> int | None:
    try:
        return int(DAEMON_PID_FILE.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def clear_daemon_pid() -> None:
    DAEMON_PID_FILE.unlink(missing_ok=True)


# Background service paths (mirrors cli.py constants — kept here to avoid circular import)
_PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / "com.signal-mcp.watch.plist"
_SYSTEMD_PATH = Path.home() / ".config" / "systemd" / "user" / "signal-mcp-watch.service"


def is_service_installed() -> bool:
    """Return True if the background message-capture service is installed."""
    return _PLIST_PATH.exists() or _SYSTEMD_PATH.exists()


# ── Webhook configuration ─────────────────────────────────────────────────────

def get_webhook_url() -> str | None:
    """Return the configured webhook URL, or None.

    Priority: SIGNAL_MCP_WEBHOOK env var → webhook.json config file.
    """
    env = os.environ.get("SIGNAL_MCP_WEBHOOK")
    if env:
        return env
    if WEBHOOK_CONFIG_FILE.exists():
        # An unreadable config is not "no webhook configured": say so rather than
        # answering None, which reads as a deliberate absence.
        try:
            data = json.loads(WEBHOOK_CONFIG_FILE.read_text())
        except Exception as exc:
            raise ToolFailure(
                f"the webhook config at {WEBHOOK_CONFIG_FILE} could not be read.",
                code="config_unreadable",
                body=f"{type(exc).__name__}: {exc}",
            ) from exc
        return data.get("url") or None
    return None


def set_webhook_url(url: str | None) -> None:
    """Persist (or clear) the webhook URL in the config file."""
    WEBHOOK_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    if url:
        WEBHOOK_CONFIG_FILE.write_text(json.dumps({"url": url}, indent=2))
    else:
        WEBHOOK_CONFIG_FILE.unlink(missing_ok=True)
