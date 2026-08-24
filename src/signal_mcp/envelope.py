"""The one failure shape every signal-mcp tool returns.

Spec: docs/MCP_FAILURE_ENVELOPE.md. One shape, every failure:

    [<code>] <one plain sentence: what did not happen>
    HTTP <status> <reason phrase>          (only when the failure really was HTTP)
    <the underlying output, verbatim>

signal-mcp drives signal-cli as a subprocess and reads local SQLite / SQLCipher
files, so most of its failures never touch HTTP. Those carry a snake_case code
and omit the status line entirely rather than inventing one (rule 4).

The body is whatever signal-cli, sqlcipher or SQLite actually said, byte for
byte, with credential-shaped values replaced by <redacted> (rule 8). It is never
summarised, translated or interpreted here: deciding what it means is the
caller's job (rule 5), and this server never suggests a remedy (rule 7).
"""

import re
import sqlite3

from mcp.types import CallToolResult, TextContent

MAX_BODY = 4000

# SQLite tells us exactly what went wrong through sqlite_errorname; nothing here
# needs to read the message prose to tell a locked database from a missing one.
_SQLITE_CODES: dict[str, str] = {
    "SQLITE_BUSY": "db_locked",
    "SQLITE_LOCKED": "db_locked",
    "SQLITE_CANTOPEN": "db_missing",
    "SQLITE_NOTADB": "db_decrypt_failed",
    "SQLITE_CORRUPT": "db_corrupt",
    "SQLITE_READONLY": "db_permission_denied",
    "SQLITE_PERM": "db_permission_denied",
    "SQLITE_AUTH": "db_permission_denied",
    "SQLITE_FULL": "db_full",
    "SQLITE_IOERR": "db_io_error",
}


def sqlite_code(exc: sqlite3.Error) -> str:
    """Map a SQLite error onto an envelope code using SQLite's own result code."""
    name = getattr(exc, "sqlite_errorname", "") or ""
    # Extended codes look like SQLITE_IOERR_READ; the primary name is the first two parts.
    primary = "_".join(name.split("_")[:2])
    return _SQLITE_CODES.get(primary, "db_error")


class ToolFailure(Exception):
    """A failure that already knows its envelope code and its verbatim evidence.

    `detail` is the second half of line 1: the caller prepends what it was doing,
    so the rendered sentence reads "Could not send the message: <detail>".
    """

    def __init__(
        self,
        detail: str,
        code: str = "unexpected_error",
        body: str | None = None,
        http: str | None = None,
    ):
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.body = body
        self.http = http

    def __str__(self) -> str:
        # str() is what the CLI prints and what a traceback shows, so the evidence
        # stays attached there too. The MCP layer reads the fields, never this.
        parts = [self.detail]
        if self.http:
            parts.append(self.http)
        if self.body:
            parts.append(redact(self.body))
        return "\n".join(parts)


# Credential-shaped values. signal-cli output and Signal Desktop's database carry
# profile keys, identity keys, registration lock material and the raw SQLCipher key;
# phone numbers stay verbatim because they are the answer, not a secret.
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    # HTTP credential headers
    (re.compile(r"(?i)\b(authorization|proxy-authorization|set-cookie|cookie)\s*:\s*[^\r\n]+"),
     r"\1: <redacted>"),
    # JSON string values, keyed by name
    (re.compile(
        r"(?i)(\"(?:access_?token|refresh_?token|client_?secret|password|passphrase|"
        r"api_?key|profile_?key|master_?key|storage_?key|session_?key|identity_?key|"
        r"private_?key|registration_?lock|pin|token|secret|key)\"\s*:\s*)\"[^\"]*\""),
     r'\1"<redacted>"'),
    # key=value / key: value outside JSON
    (re.compile(
        r"(?i)\b((?:access_?token|refresh_?token|client_?secret|password|passphrase|"
        r"api_?key|profile_?key|master_?key|storage_?key|session_?key|identity_?key|"
        r"private_?key|registration_?lock)\s*[=:]\s*)\S+"),
     r"\1<redacted>"),
    # The SQLCipher key we hand to the sqlcipher CLI, which it echoes back on a script error
    (re.compile(r"(?i)(PRAGMA\s+\w*key\s*=\s*)\S+"), r"\1<redacted>"),
    (re.compile(r"(?i)\bx'[0-9a-f]{16,}'"), "x'<redacted>'"),
    # Bare 32-byte-and-longer hex blobs are key material wherever they appear
    (re.compile(r"\b[0-9a-fA-F]{64,}\b"), "<redacted>"),
]


def redact(text: str) -> str:
    """Replace credential-shaped values with <redacted>. Everything else is untouched."""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def render(code: str, sentence: str, body: str | None = None, http: str | None = None) -> str:
    """Build the envelope text. `http` is a literal status line or None."""
    lines = [f"[{code}] {sentence}"]
    if http:
        lines.append(http)
    if body:
        # Redact before truncating so a secret straddling the cap still goes.
        evidence = redact(str(body)).strip()
        if len(evidence) > MAX_BODY:
            evidence = evidence[:MAX_BODY] + " ...[truncated]"
        if evidence:
            lines.append(evidence)
    return "\n".join(lines)


def failure(code: str, sentence: str, body: str | None = None, http: str | None = None) -> CallToolResult:
    """The MCP result for a failure: isError true, envelope text (rule 1)."""
    return CallToolResult(
        content=[TextContent(type="text", text=render(code, sentence, body, http))],
        isError=True,
    )
