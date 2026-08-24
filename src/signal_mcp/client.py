"""Async signal-cli JSON-RPC client. Single backend for all reads and writes."""

import asyncio
import itertools
import json as _json
import os
import re
import shutil
import signal
import subprocess
import sys as _sys
import time
from datetime import datetime
from pathlib import Path

import httpx

from .config import (
    ATTACHMENT_DIR,
    DAEMON_MESSAGES_LOG,
    DAEMON_PORT,
    DAEMON_STDERR_LOG,
    DAEMON_URL,
    RECEIVE_LOCK_FILE,
    clear_daemon_pid,
    detect_account,
    ensure_attachment_dir,
    read_daemon_pid,
    save_daemon_pid,
)
from .envelope import ToolFailure
from .models import Attachment, Contact, Group, GroupMember, Message, SendResult
from . import store as _store


class SignalError(ToolFailure):
    """Anything signal-cli refused, could not do, or could not be asked.

    Carries the envelope code and signal-cli's own words (rule 5), which is why
    nothing here rewrites, summarises or annotates what signal-cli said.
    """

    def __init__(self, detail: str, code: str = "signal_cli_failed",
                 body: str | None = None, http: str | None = None):
        super().__init__(detail, code=code, body=body, http=http)


# signal-cli reports the phrase below when another process already holds the receive
# lock. That is not a failure: the messages are being written to the store by whoever
# holds it. One constant, read by both the tool handler and the store freshener.
ALREADY_RECEIVING = "already being received"

_rpc_id = itertools.count(1)

# E.164 phone number validation
_E164_RE = re.compile(r"^\+[1-9]\d{6,14}$")


def _validate_e164(number: str) -> None:
    """Raise SignalError if number is not valid E.164 format."""
    if not _E164_RE.match(number):
        raise SignalError(
            f"'{number}' is not an E.164 phone number (e.g. +12125551234).",
            code="bad_request",
        )


def _send_result_failures(payload) -> list[dict]:
    """Return every non-SUCCESS per-recipient result anywhere inside a signal-cli payload.

    signal-cli reports a refused recipient as a `results` entry with a `type` other than
    SUCCESS (UNREGISTERED_FAILURE, IDENTITY_FAILURE, ...), sometimes inside a JSON-RPC
    error's `data` and sometimes inside an otherwise-200 result. This reads that field;
    it does not read the prose.
    """
    found: list[dict] = []

    def walk(node):
        if isinstance(node, dict):
            entries = node.get("results")
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict) and entry.get("type") not in (None, "SUCCESS"):
                        found.append(entry)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(payload)
    return found


def _read_daemon_stderr(limit: int = 4000) -> str:
    """Return the tail of what the signal-cli daemon last printed to stderr."""
    try:
        return DAEMON_STDERR_LOG.read_text(errors="replace")[-limit:].strip()
    except OSError as exc:
        return f"(daemon stderr log unreadable: {type(exc).__name__}: {exc})"


def _expect(result, kind: type, method: str) -> None:
    """Fail if signal-cli answered with a shape we cannot read.

    The old guards turned an unreadable answer into an empty list or dict, which
    reads downstream as "you have no groups / no accounts / no contacts" (rule 6).
    """
    if not isinstance(result, kind):
        raise SignalError(
            f"signal-cli answered '{method}' with something this server cannot read.",
            code="signal_cli_failed",
            body=_json.dumps(result, indent=2, default=str),
        )


def _send_failure_code(failures: list[dict]) -> str:
    """Map signal-cli's own per-recipient failure `type` field onto an envelope code."""
    types = {f.get("type") for f in failures}
    if types == {"UNREGISTERED_FAILURE"}:
        return "no_such_recipient"
    if types == {"IDENTITY_FAILURE"}:
        return "untrusted_identity"
    return "send_failed"


class _RateLimiter:
    """Token bucket: burst up to `rate` calls then refill at rate/per calls per second."""

    def __init__(self, rate: int = 20, per: float = 60.0):
        self._rate = rate
        self._per = per
        self._tokens = float(rate)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate / self._per)
            self._last = now
            if self._tokens < 1:
                wait = (1 - self._tokens) * self._per / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0

# Module-level contact name cache: number → display_name
_contact_cache: dict[str, str] = {}
_contact_cache_loaded: bool = False
_contact_cache_at: float = 0.0
_CACHE_TTL: float = 300.0  # refresh every 5 minutes

# Module-level group name cache: group_id → group_name
_group_cache: dict[str, str] = {}
_group_cache_loaded: bool = False
_group_cache_at: float = 0.0


_daemon_last_ok_at: float = 0.0   # monotonic timestamp of last confirmed-alive check
_DAEMON_OK_TTL: float = 5.0       # skip HTTP ping if daemon was healthy within this window


class SignalClient:
    def __init__(self, account: str | None = None, daemon_url: str = DAEMON_URL):
        self._account = account
        self._daemon_url = daemon_url
        # Pool size matches the RPC semaphore (4 concurrent RPCs).
        # connect=2.0s is tight since the daemon is localhost; read=None lets
        # per-request timeouts (passed in each _rpc call) govern read duration.
        self._http = httpx.AsyncClient(
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=4),
            timeout=httpx.Timeout(connect=2.0, read=None, write=5.0, pool=2.0),
        )
        self._rpc_sem = asyncio.Semaphore(4)   # allow up to 4 concurrent RPCs
        self._daemon_lock = asyncio.Lock()      # single-flight guard for ensure_daemon
        self._background_tasks: list[asyncio.Task] = []
        self._rate_limiter = _RateLimiter(rate=20, per=60.0)  # 20 sends/minute

    @property
    def account(self) -> str:
        if self._account is None:
            self._account = detect_account()
        return self._account

    async def close(self) -> None:
        for task in self._background_tasks:
            task.cancel()
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        self._background_tasks.clear()
        await self._http.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()

    # ── Daemon management ─────────────────────────────────────────────────────

    async def ensure_daemon(self) -> None:
        """Start signal-cli daemon if not already running (single-flight)."""
        if RECEIVE_LOCK_FILE.exists():
            return
        # TTL fast path: skip HTTP ping if daemon was healthy recently
        if time.monotonic() - _daemon_last_ok_at < _DAEMON_OK_TTL:
            return
        if await self._daemon_alive():
            return

        async with self._daemon_lock:
            # Re-check after acquiring lock: another caller may have started it
            if await self._daemon_alive():
                return

            stale_pid = read_daemon_pid()
            if stale_pid:
                try:
                    os.kill(stale_pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                clear_daemon_pid()
                await asyncio.sleep(0.5)

            # stderr goes to a log rather than /dev/null: when the daemon refuses to
            # start, what it printed is the only evidence of why (rule 5).
            try:
                DAEMON_STDERR_LOG.parent.mkdir(parents=True, exist_ok=True)
                DAEMON_STDERR_LOG.write_text("")
                with open(DAEMON_STDERR_LOG, "ab") as err_log:
                    proc = subprocess.Popen(
                        [
                            "signal-cli", "-u", self.account,
                            "daemon",
                            "--http", f"localhost:{DAEMON_PORT}",
                            "--no-receive-stdout",
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=err_log,
                    )
            except FileNotFoundError as exc:
                raise SignalError(
                    "signal-cli is not installed or not on PATH.",
                    code="not_installed",
                    body=f"{type(exc).__name__}: {exc}",
                ) from exc
            except OSError as exc:
                raise SignalError(
                    "the signal-cli daemon could not be started.",
                    code="daemon_unavailable",
                    body=f"{type(exc).__name__}: {exc}",
                ) from exc
            save_daemon_pid(proc.pid)

            for _ in range(20):
                await asyncio.sleep(0.5)
                if await self._daemon_alive():
                    return
                exit_code = proc.poll()
                if exit_code is not None:
                    # It died rather than timed out. Report why now instead of
                    # waiting out the remaining ten seconds on a dead process.
                    raise SignalError(
                        f"the signal-cli daemon exited with code {exit_code} on startup.",
                        code="daemon_unavailable",
                        body=_read_daemon_stderr(),
                    )

            raise SignalError(
                "the signal-cli daemon did not answer within 10 seconds of starting.",
                code="daemon_unavailable",
                body=_read_daemon_stderr(),
            )

    async def stop_daemon(self) -> bool:
        """Stop the running daemon. Returns True if stopped."""
        pid = read_daemon_pid()
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                clear_daemon_pid()
                return True
            except ProcessLookupError:
                clear_daemon_pid()
        try:
            result = subprocess.run(
                ["lsof", "-ti", f"tcp:{DAEMON_PORT}"],
                capture_output=True, text=True,
            )
            for pid_str in result.stdout.strip().splitlines():
                try:
                    os.kill(int(pid_str), signal.SIGTERM)
                    return True
                except (ValueError, ProcessLookupError):
                    pass
        except FileNotFoundError:
            pass
        return False

    async def _daemon_alive(self) -> bool:
        global _daemon_last_ok_at
        try:
            r = await self._http.post(
                self._daemon_url,
                json={"jsonrpc": "2.0", "method": "version", "id": 0},
                timeout=3.0,
            )
            if r.status_code == 200:
                _daemon_last_ok_at = time.monotonic()
                return True
            return False
        except Exception:
            return False

    async def prewarm(self) -> None:
        """Start daemon in background without blocking. Called at server startup."""
        task = asyncio.create_task(self.ensure_daemon())
        self._background_tasks.append(task)
        task.add_done_callback(lambda t: self._background_tasks.remove(t) if t in self._background_tasks else None)
        # Also start the watchdog (idempotent — starts only once)
        self._start_watchdog()

    def _start_watchdog(self) -> None:
        """Start the daemon watchdog background task exactly once."""
        # Check if a watchdog is already running
        for t in self._background_tasks:
            if not t.done() and getattr(t, "_is_watchdog", False):
                return
        task = asyncio.create_task(self.watchdog())
        task._is_watchdog = True  # type: ignore[attr-defined]
        self._background_tasks.append(task)
        task.add_done_callback(lambda t: self._background_tasks.remove(t) if t in self._background_tasks else None)

    async def watchdog(self) -> None:
        """Periodically check daemon health and restart if dead. Runs forever."""
        while True:
            try:
                await asyncio.sleep(30)
                if not await self._daemon_alive():
                    await self.ensure_daemon()
            except asyncio.CancelledError:
                return
            except Exception:
                pass  # best-effort; never crash the server

    # ── JSON-RPC core ─────────────────────────────────────────────────────────

    async def _rpc(self, method: str, params: dict | None = None, timeout: float = 10.0) -> dict:
        payload: dict = {
            "jsonrpc": "2.0",
            "method": method,
            "id": next(_rpc_id),
        }
        if params:
            payload["params"] = params

        async with self._rpc_sem:
            last_connect_error: Exception | None = None
            for attempt in range(2):
                try:
                    r = await self._http.post(
                        self._daemon_url, json=payload, timeout=timeout
                    )
                    r.raise_for_status()
                    break
                except httpx.ConnectError as exc:
                    last_connect_error = exc
                    if attempt == 0:
                        # Daemon may have crashed — try to restart before the second attempt
                        await self.ensure_daemon()
                except httpx.TimeoutException as exc:
                    raise SignalError(
                        f"signal-cli did not answer '{method}' within {timeout:g} seconds.",
                        code="timeout",
                        body=f"{type(exc).__name__}: {exc}",
                    ) from exc
                except httpx.HTTPStatusError as exc:
                    # The one genuinely HTTP failure in this server, so it gets the
                    # literal status line and an http_<status> code (rules 2 and 4).
                    resp = exc.response
                    raise SignalError(
                        f"the signal-cli daemon rejected '{method}'.",
                        code=f"http_{resp.status_code}",
                        body=resp.text,
                        http=f"HTTP {resp.status_code} {resp.reason_phrase}",
                    ) from exc
                except httpx.HTTPError as exc:
                    raise SignalError(
                        f"the request to the signal-cli daemon for '{method}' failed.",
                        code="daemon_unavailable",
                        body=f"{type(exc).__name__}: {exc}",
                    ) from exc
            else:
                raise SignalError(
                    "the signal-cli daemon is not accepting connections.",
                    code="daemon_unavailable",
                    body=(f"{type(last_connect_error).__name__}: {last_connect_error}"
                          if last_connect_error else None),
                )

        try:
            body = r.json()
        except ValueError as exc:
            raise SignalError(
                f"the signal-cli daemon's answer to '{method}' was not JSON.",
                code="signal_cli_failed",
                body=r.text,
            ) from exc

        if "error" in body:
            failures = _send_result_failures(body["error"])
            raise SignalError(
                f"signal-cli reported an error for '{method}'.",
                code=_send_failure_code(failures) if failures else "signal_cli_failed",
                body=_json.dumps(body["error"], indent=2, default=str),
            )

        result = body.get("result", {})
        # A 200 can still carry per-recipient refusals. Reporting that as "sent" is the
        # difference between "delivered" and "that number is not on Signal" (rule 6).
        failures = _send_result_failures(result)
        if failures:
            raise SignalError(
                f"signal-cli could not deliver to every recipient of '{method}'.",
                code=_send_failure_code(failures),
                body=_json.dumps(result, indent=2, default=str),
            )
        return result

    # ── Messaging ─────────────────────────────────────────────────────────────

    async def send_message(
        self,
        recipient: str,
        message: str,
        quote_author: str | None = None,
        quote_timestamp: int | None = None,
    ) -> SendResult:
        _validate_e164(recipient)
        await self._rate_limiter.acquire()
        params: dict = {"recipient": [recipient], "message": message}
        if quote_author and quote_timestamp:
            params["quoteAuthor"] = quote_author
            params["quoteTimestamp"] = quote_timestamp
        result = await self._rpc("send", params)
        ts = result.get("timestamp", int(time.time() * 1000))
        await asyncio.to_thread(_store.save_message, Message(
            id=f"sent_{ts}_{recipient}",
            sender=self.account,
            recipient=recipient,
            body=message,
            timestamp=datetime.fromtimestamp(ts / 1000),
            quote_id=str(quote_timestamp) if quote_timestamp else None,
        ))
        return SendResult(timestamp=ts, recipient=recipient, success=True)

    async def send_group_message(
        self,
        group_id: str,
        message: str,
        mentions: list[dict] | None = None,
        quote_author: str | None = None,
        quote_timestamp: int | None = None,
    ) -> SendResult:
        await self._rate_limiter.acquire()
        params: dict = {"groupId": group_id, "message": message}
        if mentions:
            params["mention"] = mentions
        if quote_author and quote_timestamp:
            params["quoteAuthor"] = quote_author
            params["quoteTimestamp"] = quote_timestamp
        result = await self._rpc("send", params)
        ts = result.get("timestamp", int(time.time() * 1000))
        await asyncio.to_thread(_store.save_message, Message(
            id=f"sent_{ts}_{group_id}",
            sender=self.account,
            body=message,
            timestamp=datetime.fromtimestamp(ts / 1000),
            group_id=group_id,
            quote_id=str(quote_timestamp) if quote_timestamp else None,
            is_read=True,  # sent by us, already "read"
        ))
        return SendResult(timestamp=ts, recipient=group_id, success=True)

    async def send_note_to_self(self, message: str) -> SendResult:
        """Send a note to yourself (saved messages)."""
        return await self.send_message(self.account, message)

    async def send_attachment(
        self,
        recipient: str,
        path: str | list[str],
        caption: str = "",
        view_once: bool = False,
    ) -> SendResult:
        _validate_e164(recipient)
        await self._rate_limiter.acquire()
        paths = [path] if isinstance(path, str) else path
        resolved = [str(Path(p).expanduser().resolve()) for p in paths]
        params: dict = {"recipient": [recipient], "attachment": resolved}
        if caption:
            params["message"] = caption
        if view_once:
            params["viewOnce"] = True
        result = await self._rpc("send", params)
        ts = result.get("timestamp", int(time.time() * 1000))
        await asyncio.to_thread(_store.save_message, Message(
            id=f"sent_{ts}_{recipient}",
            sender=self.account,
            recipient=recipient,
            body=caption,
            timestamp=datetime.fromtimestamp(ts / 1000),
        ))
        return SendResult(timestamp=ts, recipient=recipient, success=True)

    async def send_group_attachment(
        self,
        group_id: str,
        path: str | list[str],
        caption: str = "",
        view_once: bool = False,
    ) -> SendResult:
        await self._rate_limiter.acquire()
        paths = [path] if isinstance(path, str) else path
        resolved = [str(Path(p).expanduser().resolve()) for p in paths]
        params: dict = {"groupId": group_id, "attachment": resolved}
        if caption:
            params["message"] = caption
        if view_once:
            params["viewOnce"] = True
        result = await self._rpc("send", params)
        ts = result.get("timestamp", int(time.time() * 1000))
        await asyncio.to_thread(_store.save_message, Message(
            id=f"sent_{ts}_{group_id}",
            sender=self.account,
            body=caption,
            timestamp=datetime.fromtimestamp(ts / 1000),
            group_id=group_id,
            is_read=True,  # sent by us, already "read"
        ))
        return SendResult(timestamp=ts, recipient=group_id, success=True)

    async def send_sticker(
        self, recipient: str, pack_id: str, sticker_id: int
    ) -> SendResult:
        """Send a sticker to a contact."""
        _validate_e164(recipient)
        await self._rate_limiter.acquire()
        params: dict = {
            "recipient": [recipient],
            "sticker": f"{pack_id}:{sticker_id}",
        }
        result = await self._rpc("send", params)
        ts = result.get("timestamp", int(time.time() * 1000))
        await asyncio.to_thread(_store.save_message, Message(
            id=f"sent_{ts}_{recipient}",
            sender=self.account,
            recipient=recipient,
            body=f"[sticker {pack_id}:{sticker_id}]",
            timestamp=datetime.fromtimestamp(ts / 1000),
        ))
        return SendResult(timestamp=ts, recipient=recipient, success=True)

    async def send_group_sticker(
        self, group_id: str, pack_id: str, sticker_id: int
    ) -> SendResult:
        """Send a sticker to a group."""
        await self._rate_limiter.acquire()
        params: dict = {
            "groupId": group_id,
            "sticker": f"{pack_id}:{sticker_id}",
        }
        result = await self._rpc("send", params)
        ts = result.get("timestamp", int(time.time() * 1000))
        await asyncio.to_thread(_store.save_message, Message(
            id=f"sent_{ts}_{group_id}",
            sender=self.account,
            body=f"[sticker {pack_id}:{sticker_id}]",
            timestamp=datetime.fromtimestamp(ts / 1000),
            group_id=group_id,
            is_read=True,  # sent by us, already "read"
        ))
        return SendResult(timestamp=ts, recipient=group_id, success=True)

    def list_attachments(self) -> list[dict]:
        """List all downloaded attachments in the attachments directory."""
        att_dir = ATTACHMENT_DIR
        if not att_dir.exists():
            return []
        files = []
        for p in sorted(att_dir.iterdir()):
            if p.is_file():
                stat = p.stat()
                files.append({
                    "filename": p.name,
                    "path": str(p),
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
        return files

    def get_attachment(self, filename: str) -> dict:
        """Get info about a specific downloaded attachment by filename."""
        att_dir = ATTACHMENT_DIR
        # Resolve to prevent path traversal (e.g. "../secret")
        path = (att_dir / filename).resolve()
        if path.parent != att_dir.resolve():
            raise SignalError(
                f"'{filename}' is not a name inside the Signal attachments folder.",
                code="bad_request",
            )
        if not path.exists() or not path.is_file():
            raise SignalError(
                f"there is no downloaded attachment named '{filename}'.",
                code="not_found",
                body=f"Looked in: {att_dir}",
            )
        stat = path.stat()
        return {
            "filename": path.name,
            "path": str(path),
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }

    async def set_typing(self, recipient: str, stop: bool = False) -> None:
        action = "STOPPED" if stop else "STARTED"
        await self._rpc("sendTyping", {"recipient": [recipient], "action": action})

    async def react_to_message(
        self,
        target_author: str,
        target_timestamp: int,
        emoji: str,
        recipient: str | None = None,
        group_id: str | None = None,
        remove: bool = False,
    ) -> None:
        if not recipient and not group_id:
            raise SignalError("Either recipient or group_id must be provided")
        params: dict = {
            "emoji": emoji,
            "targetAuthor": target_author,
            "targetTimestamp": target_timestamp,
            "remove": remove,
        }
        if group_id:
            params["groupId"] = group_id
        else:
            params["recipient"] = [recipient]
        await self._rpc("sendReaction", params)

    async def receive_messages(self, timeout: int = 5) -> list[Message]:
        """Poll for new messages and persist them to local store."""
        result = await self._rpc("receive", {"timeout": timeout}, timeout=timeout + 5.0)
        _expect(result, list, "receive")
        messages = []
        for envelope in result:
            # Intercept incoming edits: update existing message body rather than saving a new ghost
            data = envelope.get("envelope", envelope)
            edit_sender = data.get("source", "") or data.get("sourceNumber", "")
            dm = data.get("dataMessage") or {}
            edit = dm.get("editMessage")
            if not edit:
                sync_sent = (data.get("syncMessage") or {}).get("sentMessage") or {}
                edit = sync_sent.get("editMessage")
                if edit:
                    edit_sender = self.account  # sync edits originated from us
            if edit:
                target_ts = edit.get("targetSentTimestamp")
                new_body = (edit.get("dataMessage") or {}).get("message", "") or ""
                if target_ts:
                    await asyncio.to_thread(
                        _store.update_message_body, target_ts, new_body, edit_sender or None
                    )
                continue

            msg = self._parse_envelope(envelope)
            if msg:
                if not msg.receipt_type:
                    await asyncio.to_thread(_store.save_message, msg)
                messages.append(msg)
        return messages

    async def receive_direct(self, timeout: int = 5) -> list[Message]:
        """Receive messages by calling signal-cli directly (no daemon).

        Stops any running daemon first to release the receive lock, then
        invokes ``signal-cli receive`` as a subprocess.  A lockfile prevents
        other processes from restarting the daemon during the receive window.
        """
        RECEIVE_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        RECEIVE_LOCK_FILE.write_text(str(os.getpid()))
        try:
            await self.stop_daemon()
            await asyncio.sleep(0.5)

            try:
                proc = await asyncio.create_subprocess_exec(
                    "signal-cli", "-u", self.account, "-o", "json",
                    "receive", "--timeout", str(timeout),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError as exc:
                raise SignalError(
                    "signal-cli is not installed or not on PATH.",
                    code="not_installed",
                    body=f"{type(exc).__name__}: {exc}",
                ) from exc
            stdout, stderr = await proc.communicate()
        finally:
            RECEIVE_LOCK_FILE.unlink(missing_ok=True)

        # A non-zero signal-cli is not "no new messages": an empty list here would read
        # as an empty inbox to whoever asked (rule 6).
        if proc.returncode != 0:
            raise SignalError(
                f"signal-cli receive exited with code {proc.returncode}.",
                code="signal_cli_failed",
                body=stderr.decode(errors="replace").strip(),
            )

        messages: list[Message] = []
        undecodable: list[str] = []
        for line in stdout.decode().strip().splitlines():
            if not line.strip():
                continue
            try:
                envelope = _json.loads(line)
            except _json.JSONDecodeError:
                undecodable.append(line)
                continue
            msg = self._parse_envelope(envelope)
            if msg:
                if not msg.receipt_type:
                    await asyncio.to_thread(_store.save_message, msg)
                messages.append(msg)
        if undecodable and not messages:
            raise SignalError(
                "signal-cli receive printed nothing this server could read as a message.",
                code="signal_cli_failed",
                body="\n".join(undecodable),
            )
        return messages

    def _parse_envelope(self, envelope: dict) -> Message | None:
        data = envelope.get("envelope", envelope)
        sender = data.get("source", "") or data.get("sourceNumber", "")
        ts_ms = data.get("timestamp", 0)

        # Delivery/read receipts
        receipt = data.get("receiptMessage")
        if receipt:
            receipt_type = receipt.get("type", "DELIVERY")
            return Message(
                id=f"receipt_{ts_ms}_{sender}",
                sender=sender,
                body="",
                timestamp=datetime.fromtimestamp(ts_ms / 1000),
                receipt_type=receipt_type,
            )

        # Typing indicators and call messages — acknowledge but don't store
        if data.get("typingMessage") or data.get("callMessage"):
            return None

        # Sync messages: sent from a linked device — store as outgoing
        sync = data.get("syncMessage")
        if sync:
            sent = sync.get("sentMessage")
            if not sent:
                return None  # read/delivered sync — not a message we store
            data_message = sent
            sender = self.account  # it was sent by us
            ts_ms = sent.get("timestamp", ts_ms)
            recipient = sent.get("destination") or sent.get("destinationNumber")
            attachments = self._parse_attachments(data_message)
            quote = data_message.get("quote") or {}
            return Message(
                id=str(ts_ms),
                sender=sender,
                recipient=recipient,
                body=data_message.get("message", "") or "",
                timestamp=datetime.fromtimestamp(ts_ms / 1000),
                attachments=attachments,
                group_id=data_message.get("groupInfo", {}).get("groupId"),
                quote_id=str(quote["id"]) if quote.get("id") else None,
                is_read=True,  # sent by us, already "read"
            )

        data_message = data.get("dataMessage")
        if not data_message:
            return None

        # Reaction envelopes: someone reacted to a message — don't store as text
        if data_message.get("reaction"):
            return None

        attachments = self._parse_attachments(data_message)
        ts_ms = data_message.get("timestamp", ts_ms)
        quote = data_message.get("quote") or {}
        return Message(
            id=str(ts_ms),
            sender=sender,
            body=data_message.get("message", "") or "",
            timestamp=datetime.fromtimestamp(ts_ms / 1000),
            attachments=attachments,
            group_id=data_message.get("groupInfo", {}).get("groupId"),
            quote_id=str(quote["id"]) if quote.get("id") else None,
            expires_in_seconds=data_message.get("expiresInSeconds") or None,
            view_once=bool(data_message.get("viewOnce", False)),
        )

    def _parse_attachments(self, data_message: dict) -> list[Attachment]:
        """Extract and copy attachments from a dataMessage/sentMessage dict."""
        attachments = []
        for att in data_message.get("attachments", []):
            local_path = att.get("filename")
            caption = att.get("caption")
            if local_path:
                dest = ensure_attachment_dir() / Path(local_path).name
                try:
                    shutil.copy2(local_path, dest)
                    local_path = str(dest)
                except OSError as exc:
                    # The message itself is fine, so this must not fail the whole receive.
                    # But a path we could not copy is not a path anyone can open later:
                    # say so on the attachment rather than handing back a dead one.
                    local_path = None
                    note = f"[attachment not saved locally: {type(exc).__name__}: {exc}]"
                    caption = f"{caption} {note}" if caption else note
            attachments.append(Attachment(
                content_type=att.get("contentType", "application/octet-stream"),
                filename=att.get("filename", ""),
                local_path=local_path,
                size=att.get("size"),
                width=att.get("width"),
                height=att.get("height"),
                caption=caption,
            ))
        return attachments

    # ── Contact name resolution ───────────────────────────────────────────────

    async def _ensure_contact_cache(self) -> None:
        """Load contacts into module-level cache.

        Only marks the cache as loaded on success — failures allow retry on
        next call so a cold-start race (daemon not yet up) doesn't permanently
        freeze the cache empty.  Cache expires after _CACHE_TTL seconds so
        contact name changes are picked up mid-session.
        """
        global _contact_cache, _contact_cache_loaded, _contact_cache_at
        now = time.monotonic()
        if _contact_cache_loaded and (now - _contact_cache_at) < _CACHE_TTL:
            return
        try:
            contacts = await self.list_contacts()
            for c in contacts:
                if c.number:
                    _contact_cache[c.number] = c.display_name
                if c.uuid:
                    _contact_cache[c.uuid] = c.display_name
            _contact_cache_loaded = True   # only set on success
            _contact_cache_at = time.monotonic()
        except SignalError:
            # Names are enrichment on top of an answer, never the answer, so a cold
            # daemon must not fail the caller's read. Narrow to SignalError so a bug
            # in here is not swallowed with it; the cache retries on the next call.
            pass

    async def _ensure_group_cache(self) -> None:
        """Load group names into module-level cache (TTL same as contact cache)."""
        global _group_cache, _group_cache_loaded, _group_cache_at
        now = time.monotonic()
        if _group_cache_loaded and (now - _group_cache_at) < _CACHE_TTL:
            return
        try:
            groups = await self.list_groups()
            for g in groups:
                if g.id:
                    _group_cache[g.id] = g.name or g.id
            _group_cache_loaded = True
            _group_cache_at = time.monotonic()
        except SignalError:
            pass  # same as the contact cache: enrichment, retried next call

    async def _ensure_caches(self) -> None:
        """Load contact and group name caches concurrently (parallel RPC calls)."""
        await asyncio.gather(
            self._ensure_contact_cache(),
            self._ensure_group_cache(),
        )

    def resolve_name(self, number: str) -> str:
        """Return display name for a number, or the number itself if unknown."""
        return _contact_cache.get(number, number)

    def resolve_group_name(self, group_id: str) -> str:
        """Return group name for a group_id, or the group_id itself if unknown."""
        return _group_cache.get(group_id, group_id)

    def _enrich_message(self, msg: Message) -> dict:
        """Convert message to dict and add resolved display names."""
        d = msg.to_dict()
        d["sender_name"] = self.resolve_name(msg.sender)
        if msg.recipient:
            d["recipient_name"] = self.resolve_name(msg.recipient)
        if msg.group_id:
            d["group_name"] = self.resolve_group_name(msg.group_id)
        return d

    # ── Contacts ──────────────────────────────────────────────────────────────

    async def list_contacts(self, search: str | None = None) -> list[Contact]:
        result = await self._rpc("listContacts")
        _expect(result, list, "listContacts")
        contacts = []
        for c in result:
            profile = c.get("profile") or {}
            contacts.append(Contact(
                number=c.get("number") or "",
                uuid=c.get("uuid"),
                name=(c.get("name") or "").strip() or None,
                given_name=(profile.get("givenName") or c.get("givenName") or "").strip() or None,
                family_name=(profile.get("familyName") or c.get("familyName") or "").strip() or None,
                profile_name=None,
                about=(profile.get("about") or c.get("about") or "").strip() or None,
                blocked=c.get("isBlocked", False),
            ))
        if search:
            q = search.lower()
            contacts = [
                c for c in contacts
                if q in (c.number or "").lower()
                or q in (c.name or "").lower()
                or q in (c.given_name or "").lower()
                or q in (c.family_name or "").lower()
            ]
        return contacts

    async def get_profile(self, number: str) -> Contact:
        result = await self._rpc("getUserStatus", {"recipient": [number]})
        entries = result if isinstance(result, list) else [result]
        for entry in entries:
            if entry.get("number") == number or entry.get("uuid"):
                profile = entry.get("profile") or {}
                return Contact(
                    number=number,
                    uuid=entry.get("uuid"),
                    name=(entry.get("name") or "").strip() or None,
                    given_name=(profile.get("givenName") or "").strip() or None,
                    family_name=(profile.get("familyName") or "").strip() or None,
                )
        return Contact(number=number)

    async def block_contact(self, number: str) -> None:
        await self._rpc("block", {"recipient": [number]})

    async def unblock_contact(self, number: str) -> None:
        await self._rpc("unblock", {"recipient": [number]})

    async def remove_contact(self, number: str) -> None:
        await self._rpc("removeContact", {"recipient": number})

    async def update_profile(
        self,
        name: str | None = None,
        about: str | None = None,
        avatar_path: str | None = None,
        remove_avatar: bool = False,
    ) -> None:
        params: dict = {}
        if name is not None:
            params["name"] = name
        if about is not None:
            params["about"] = about
        if avatar_path is not None:
            params["avatarPath"] = str(Path(avatar_path).expanduser().resolve())
        if remove_avatar:
            params["removeAvatar"] = True
        await self._rpc("updateProfile", params or None)

    # ── Groups ────────────────────────────────────────────────────────────────

    async def list_groups(self) -> list[Group]:
        result = await self._rpc("listGroups")
        _expect(result, list, "listGroups")
        groups = []
        for g in result:
            members = [
                GroupMember(
                    uuid=m.get("uuid", ""),
                    number=m.get("number"),
                    is_admin=m.get("isAdmin", False),
                )
                for m in g.get("members", [])
                if m.get("uuid")
            ]
            admin_uuids = [a.get("uuid", "") for a in g.get("admins", [])]
            groups.append(Group(
                id=g.get("id") or "",
                name=g.get("name") or "",
                members=members,
                description=g.get("description") or None,
                is_blocked=g.get("isBlocked", False),
                is_member=g.get("isMember", True),
                admins=admin_uuids,
                invite_link=g.get("groupInviteLink") or None,
            ))
        return groups

    async def create_group(
        self,
        name: str,
        members: list[str],
        description: str | None = None,
    ) -> dict:
        """Create a new Signal group. Returns the new group info."""
        params: dict = {"name": name, "member": members}
        if description:
            params["description"] = description
        result = await self._rpc("updateGroup", params)
        _expect(result, dict, "updateGroup")
        return result

    async def update_group(
        self,
        group_id: str,
        name: str | None = None,
        description: str | None = None,
        add_members: list[str] | None = None,
        remove_members: list[str] | None = None,
        expiration_seconds: int | None = None,
        add_admins: list[str] | None = None,
        remove_admins: list[str] | None = None,
        link_mode: str | None = None,
    ) -> None:
        """Update group properties (name, description, members, admins, expiry timer, invite link)."""
        params: dict = {"groupId": group_id}
        if name is not None:
            params["name"] = name
        if description is not None:
            params["description"] = description
        if add_members:
            params["member"] = add_members
        if remove_members:
            params["removeMember"] = remove_members
        if expiration_seconds is not None:
            params["expiration"] = expiration_seconds
        if add_admins:
            params["admin"] = add_admins
        if remove_admins:
            params["removeAdmin"] = remove_admins
        if link_mode is not None:
            # Values: "disabled", "enabled", "enabled-with-approval", "reset"
            params["link"] = link_mode
        await self._rpc("updateGroup", params)

    async def join_group(self, uri: str) -> dict:
        """Join a group via invite link URI."""
        result = await self._rpc("joinGroup", {"uri": uri})
        _expect(result, dict, "joinGroup")
        return result

    async def list_devices(self) -> list[dict]:
        """List all linked devices on this account."""
        result = await self._rpc("listDevices")
        return result if isinstance(result, list) else [result] if result else []

    async def add_device(self, uri: str) -> None:
        """Link a new device using a device link URI (from signal-cli link output)."""
        await self._rpc("addDevice", {"uri": uri})

    async def remove_device(self, device_id: int) -> None:
        """Unlink a device by its ID (get IDs from list_devices)."""
        await self._rpc("removeDevice", {"deviceId": device_id})

    # ── History & Search ──────────────────────────────────────────────────────

    async def get_conversation(
        self, recipient: str, limit: int = 50, offset: int = 0, since: datetime | None = None
    ) -> list[Message]:
        messages = await asyncio.to_thread(
            _store.get_conversation, recipient, limit=limit, offset=offset, since=since
        )
        # Auto-mark received messages as read (like every Signal client does)
        unread_ids = [m.id for m in messages if not m.is_read and m.sender != self.account]
        if unread_ids:
            await asyncio.to_thread(_store.mark_as_read, unread_ids)
            for m in messages:
                if m.id in unread_ids:
                    m.is_read = True
        return messages

    async def search_messages(
        self, query: str, limit: int = 50, offset: int = 0, sender: str | None = None
    ) -> list[Message]:
        return await asyncio.to_thread(_store.search_messages, query, limit=limit, offset=offset, sender=sender)

    async def list_conversations(self) -> list[dict]:
        convs = await asyncio.to_thread(_store.list_conversations, own_number=self.account)
        for conv in convs:
            if conv["type"] == "direct":
                conv["name"] = self.resolve_name(conv["id"])
            elif conv["type"] == "group":
                conv["name"] = self.resolve_group_name(conv["id"])
        return convs

    async def clear_local_store(self) -> int:
        """Delete all locally stored messages. Returns count deleted."""
        return await asyncio.to_thread(_store.clear_store)

    async def delete_local_messages(self, recipient: str) -> int:
        """Delete locally stored messages for one contact or group. Returns count deleted."""
        return await asyncio.to_thread(_store.delete_conversation_messages, recipient)

    async def export_messages(
        self,
        fmt: str = "json",
        recipient: str | None = None,
        since: datetime | None = None,
    ) -> str:
        """Export messages as JSON or CSV text, with sender/group names resolved."""
        await self._ensure_caches()
        messages = await asyncio.to_thread(_store.get_messages_for_export, recipient, since)
        enriched = [self._enrich_message(m) for m in messages]
        return await asyncio.to_thread(_store.export_messages, fmt, recipient, since, enriched)

    async def get_unread_messages(self, limit: int = 50) -> list[Message]:
        # NOTE: does NOT auto-mark as read — the server handler does that explicitly
        # after trimming the limit+1 probe, preventing the extra message from being
        # silently consumed.
        return await asyncio.to_thread(_store.get_unread_messages, own_number=self.account, limit=limit)

    def get_own_number(self) -> str:
        return self.account

    async def get_user_status(self, recipients: list[str]) -> list[dict]:
        """Check whether phone numbers are registered Signal users."""
        result = await self._rpc("getUserStatus", {"recipients": recipients})
        _expect(result, list, "getUserStatus")
        return result

    async def send_sync_request(self) -> None:
        """Request a sync of messages/contacts/groups from the primary device."""
        await self._rpc("sendSyncRequest")

    # ── Configuration ─────────────────────────────────────────────────────────

    async def get_configuration(self) -> dict:
        """Return current Signal account configuration flags."""
        result = await self._rpc("getConfiguration")
        _expect(result, dict, "getConfiguration")
        return result

    async def update_configuration(
        self,
        read_receipts: bool | None = None,
        typing_indicators: bool | None = None,
        link_previews: bool | None = None,
        unidentified_delivery_indicators: bool | None = None,
    ) -> None:
        """Toggle account-level configuration flags."""
        params: dict = {}
        if read_receipts is not None:
            params["readReceipts"] = read_receipts
        if typing_indicators is not None:
            params["typingIndicators"] = typing_indicators
        if link_previews is not None:
            params["linkPreviews"] = link_previews
        if unidentified_delivery_indicators is not None:
            params["unidentifiedDeliveryIndicators"] = unidentified_delivery_indicators
        if params:
            await self._rpc("updateConfiguration", params)

    # ── Sticker packs ─────────────────────────────────────────────────────────

    async def list_sticker_packs(self) -> list[dict]:
        """List all installed sticker packs."""
        result = await self._rpc("listStickerPacks")
        _expect(result, list, "listStickerPacks")
        return result

    async def add_sticker_pack(self, uri: str) -> None:
        """Install a sticker pack from a signal.art URL."""
        await self._rpc("addStickerPack", {"uri": uri})

    async def get_sticker(self, pack_id: str, sticker_id: int) -> str:
        """Get a single sticker image as a base64-encoded string."""
        result = await self._rpc("getSticker", {"packId": pack_id, "stickerId": sticker_id})
        data = result.get("base64") if isinstance(result, dict) else result
        if not data:
            raise SignalError(
                f"signal-cli returned no image for sticker {pack_id}:{sticker_id}.",
                code="signal_cli_failed",
                body=_json.dumps(result, indent=2, default=str),
            )
        return str(data)

    async def upload_sticker_pack(self, path: str) -> str:
        """Upload a sticker pack from a local manifest.json or zip file.

        Returns the signal.art URL for the published pack.
        """
        resolved = str(Path(path).expanduser().resolve())
        result = await self._rpc("uploadStickerPack", {"path": resolved})
        url = result.get("url") if isinstance(result, dict) else result
        if not url:
            raise SignalError(
                "signal-cli returned no signal.art URL for the uploaded sticker pack.",
                code="signal_cli_failed",
                body=_json.dumps(result, indent=2, default=str),
            )
        return str(url)

    async def list_accounts(self) -> list[str]:
        """List all phone numbers (accounts) configured in signal-cli."""
        result = await self._rpc("listAccounts")
        _expect(result, list, "listAccounts")
        return [entry.get("number") or entry for entry in result if entry]

    async def update_account(
        self,
        device_name: str | None = None,
        discoverable_by_number: bool | None = None,
        number_sharing: bool | None = None,
        username: str | None = None,
        delete_username: bool = False,
        unrestricted_unidentified_sender: bool | None = None,
    ) -> None:
        """Update account-level settings."""
        params: dict = {}
        if device_name is not None:
            params["deviceName"] = device_name
        if discoverable_by_number is not None:
            params["discoverableByNumber"] = discoverable_by_number
        if number_sharing is not None:
            params["numberSharing"] = number_sharing
        if delete_username:
            params["deleteUsername"] = True
        elif username is not None:
            params["username"] = username
        if unrestricted_unidentified_sender is not None:
            params["unrestrictedUnidentifiedSender"] = unrestricted_unidentified_sender
        await self._rpc("updateAccount", params or None)

    async def set_pin(self, pin: str) -> None:
        """Set the Signal registration lock PIN."""
        await self._rpc("setPin", {"pin": pin})

    async def remove_pin(self) -> None:
        """Remove the Signal registration lock PIN."""
        await self._rpc("removePin")

    # ── Streaming receive ─────────────────────────────────────────────────────

    async def receive_stream(self, poll_interval: int = 2):
        """Async generator: yield messages continuously, polling every poll_interval seconds."""
        while True:
            try:
                msgs = await self.receive_messages(timeout=poll_interval)
                for msg in msgs:
                    yield msg
            except asyncio.CancelledError:
                return
            except Exception as exc:
                # The watch loop must survive a flaky daemon, but a poll that keeps
                # failing has to be visible somewhere rather than looking like silence.
                print(f"[signal-mcp] receive poll failed: {type(exc).__name__}: {exc}",
                      file=_sys.stderr, flush=True)
                await asyncio.sleep(poll_interval)

    # ── Message actions ───────────────────────────────────────────────────────

    async def delete_message(self, recipient: str, target_timestamp: int) -> None:
        await self._rpc("remoteDelete", {
            "recipient": [recipient],
            "targetTimestamp": target_timestamp,
        })

    async def delete_group_message(self, group_id: str, target_timestamp: int) -> None:
        await self._rpc("remoteDelete", {
            "groupId": group_id,
            "targetTimestamp": target_timestamp,
        })

    async def edit_message(
        self,
        target_timestamp: int,
        message: str,
        recipient: str | None = None,
        group_id: str | None = None,
    ) -> None:
        """Edit a previously sent message and update the local store."""
        if not recipient and not group_id:
            raise SignalError("Either recipient or group_id must be provided")
        params: dict = {"targetTimestamp": target_timestamp, "message": message}
        if group_id:
            params["groupId"] = group_id
        else:
            params["recipient"] = [recipient]
        await self._rpc("editMessage", params)
        await asyncio.to_thread(_store.update_message_body, target_timestamp, message, self.account)

    async def send_read_receipt(self, sender: str, timestamps: list[int]) -> None:
        await self._rpc("sendReceipt", {
            "recipient": sender,
            "targetTimestamp": timestamps,
            "receiptType": "read",
        })
        # Mark as read in local store — received message IDs are str(timestamp_ms)
        await asyncio.to_thread(_store.mark_as_read, [str(ts) for ts in timestamps])

    async def set_expiration_timer(
        self, recipient: str | None = None, group_id: str | None = None, expiration: int = 0
    ) -> None:
        """Set disappearing message timer (seconds). 0 disables."""
        if group_id:
            await self.update_group(group_id, expiration_seconds=expiration)
        elif recipient:
            await self._rpc("updateContact", {
                "recipient": recipient,
                "expiration": expiration,
            })
        else:
            raise SignalError("Either recipient or group_id must be provided")

    async def update_contact(self, number: str, name: str) -> None:
        await self._rpc("updateContact", {
            "recipient": number,
            "name": name,
        })

    async def leave_group(self, group_id: str) -> None:
        await self._rpc("quitGroup", {"groupId": group_id})

    async def pin_message(
        self,
        target_author: str,
        target_timestamp: int,
        recipient: str | None = None,
        group_id: str | None = None,
    ) -> None:
        """Pin a message in a group or DM conversation."""
        if not recipient and not group_id:
            raise SignalError("Either recipient or group_id must be provided")
        params: dict = {"targetAuthor": target_author, "targetTimestamp": target_timestamp}
        if group_id:
            params["groupId"] = group_id
        else:
            params["recipient"] = [recipient]
        await self._rpc("sendPinMessage", params)

    async def unpin_message(
        self,
        target_author: str,
        target_timestamp: int,
        recipient: str | None = None,
        group_id: str | None = None,
    ) -> None:
        """Unpin a message in a group or DM conversation."""
        if not recipient and not group_id:
            raise SignalError("Either recipient or group_id must be provided")
        params: dict = {"targetAuthor": target_author, "targetTimestamp": target_timestamp}
        if group_id:
            params["groupId"] = group_id
        else:
            params["recipient"] = [recipient]
        await self._rpc("sendUnpinMessage", params)

    async def admin_delete_message(
        self,
        target_author: str,
        target_timestamp: int,
        group_id: str,
    ) -> None:
        """Group admin: delete any message in a group (sendAdminDelete)."""
        await self._rpc("sendAdminDelete", {
            "groupId": group_id,
            "targetAuthor": target_author,
            "targetTimestamp": target_timestamp,
        })

    async def send_contacts_sync(self) -> None:
        """Sync contacts list to all linked devices."""
        await self._rpc("sendContacts")

    async def update_device(self, device_id: int, name: str) -> None:
        """Rename a linked device."""
        await self._rpc("updateDevice", {"deviceId": device_id, "name": name})

    # ── Local store extras ────────────────────────────────────────────────────

    async def mark_as_unread(self, message_ids: list[str]) -> None:
        """Mark messages as unread in the local store."""
        await asyncio.to_thread(_store.mark_as_unread, message_ids)

    # ── Avatar ────────────────────────────────────────────────────────────────

    async def get_avatar(self, identifier: str) -> str:
        """Get avatar for a contact (phone number) or group (group_id) as base64.

        Returns the base64-encoded image string, or empty string if none.
        """
        # signal-cli distinguishes contact avatars vs group avatars by param name
        if identifier.startswith("+"):
            result = await self._rpc("getAvatar", {"recipient": identifier})
        else:
            result = await self._rpc("getAvatar", {"groupId": identifier})
        if isinstance(result, dict):
            return result.get("base64", "") or ""
        return str(result) if result else ""

    # ── Message requests ──────────────────────────────────────────────────────

    async def send_message_request_response(
        self, sender: str, accept: bool
    ) -> None:
        """Accept or decline a message request from an unknown contact.

        Signal requires this before you can reply to someone not in your contacts.
        accept=True to accept (start chatting), accept=False to decline/block.
        """
        await self._rpc("sendMessageRequestResponse", {
            "recipient": [sender],
            "type": "accept" if accept else "delete",
        })

    # ── Polls ─────────────────────────────────────────────────────────────────

    async def create_poll(
        self,
        question: str,
        options: list[str],
        recipient: str | None = None,
        group_id: str | None = None,
        multi_select: bool = False,
    ) -> SendResult:
        """Create a poll and send it to a contact or group."""
        if not recipient and not group_id:
            raise SignalError("Either recipient or group_id must be provided")
        await self._rate_limiter.acquire()
        params: dict = {
            "poll-question": question,
            "poll-options": options,
        }
        if multi_select:
            params["poll-multi-select"] = True
        if group_id:
            params["groupId"] = group_id
        else:
            params["recipient"] = [recipient]
        result = await self._rpc("sendPollCreate", params)
        ts = result.get("timestamp", int(time.time() * 1000)) if isinstance(result, dict) else int(time.time() * 1000)
        return SendResult(timestamp=ts, recipient=group_id or recipient or "", success=True)

    async def vote_poll(
        self,
        target_author: str,
        target_timestamp: int,
        poll_id: int,
        votes: list[int],
        recipient: str | None = None,
        group_id: str | None = None,
    ) -> None:
        """Vote on an existing poll."""
        if not recipient and not group_id:
            raise SignalError("Either recipient or group_id must be provided")
        params: dict = {
            "targetAuthor": target_author,
            "targetTimestamp": target_timestamp,
            "poll-id": poll_id,
            "poll-answer": votes,
        }
        if group_id:
            params["groupId"] = group_id
        else:
            params["recipient"] = [recipient]
        await self._rpc("sendPollVote", params)

    async def terminate_poll(
        self,
        target_author: str,
        target_timestamp: int,
        poll_id: int,
        recipient: str | None = None,
        group_id: str | None = None,
    ) -> None:
        """Terminate (end) a poll you created."""
        if not recipient and not group_id:
            raise SignalError("Either recipient or group_id must be provided")
        params: dict = {
            "targetAuthor": target_author,
            "targetTimestamp": target_timestamp,
            "poll-id": poll_id,
        }
        if group_id:
            params["groupId"] = group_id
        else:
            params["recipient"] = [recipient]
        await self._rpc("sendPollTerminate", params)

    # ── Identity / safety numbers ─────────────────────────────────────────────

    async def list_identities(self, number: str | None = None) -> list[dict]:
        params = {"recipient": number} if number else {}
        result = await self._rpc("listIdentities", params or None)
        return result if isinstance(result, list) else [result] if result else []

    async def trust_identity(self, number: str, trust_all_known: bool = False, safety_number: str | None = None) -> None:
        params: dict = {"recipient": number}
        if safety_number:
            params["verifiedSafetyNumber"] = safety_number
        else:
            params["trustAllKnownKeys"] = trust_all_known
        await self._rpc("trust", params)

    # ── Account / number change ───────────────────────────────────────────────

    async def start_change_number(
        self, number: str, voice: bool = False, captcha: str | None = None
    ) -> None:
        """Initiate a phone number change. Signal will send a verification code."""
        params: dict = {"number": number}
        if voice:
            params["voice"] = True
        if captcha:
            params["captcha"] = captcha
        await self._rpc("startChangeNumber", params)

    async def finish_change_number(
        self, number: str, verification_code: str, pin: str | None = None
    ) -> None:
        """Complete a phone number change using the verification code."""
        params: dict = {"number": number, "verificationCode": verification_code}
        if pin:
            params["pin"] = pin
        await self._rpc("finishChangeNumber", params)

    async def submit_rate_limit_challenge(self, challenge: str, captcha: str) -> None:
        """Submit a rate-limit challenge token + solved captcha to unblock the account."""
        await self._rpc("submitRateLimitChallenge", {
            "challenge": challenge,
            "captcha": captcha,
        })

    # ── Scheduled messages ────────────────────────────────────────────────────

    async def process_scheduled_messages(self) -> list[dict]:
        """Send any scheduled messages that are due now. Returns list of results."""
        from datetime import datetime as _dt
        from . import store as _store

        due = _store.get_pending_scheduled(now=_dt.now())
        results = []
        for job in due:
            try:
                await self.ensure_daemon()
                if job["group_id"]:
                    result = await self.send_group_message(job["group_id"], job["message"])
                else:
                    result = await self.send_message(job["recipient"], job["message"])
                _store.mark_scheduled_sent(job["id"])
                results.append({"id": job["id"], "status": "sent", "timestamp": result.timestamp})
            except Exception as e:
                _store.mark_scheduled_failed(job["id"], str(e))
                results.append({"id": job["id"], "status": "failed", "error": str(e)})
        return results
