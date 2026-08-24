"""Helpers for asserting on the uniform failure envelope (docs/MCP_FAILURE_ENVELOPE.md)."""

import re

from mcp.types import CallToolResult

_CODE_RE = re.compile(r"^\[([a-z0-9_]+)\] ")


def result_text(result) -> str:
    """The text of a tool result, whichever shape it came back in."""
    if isinstance(result, CallToolResult):
        return result.content[0].text
    return result[0].text


def failure(result) -> tuple[str, str]:
    """Assert *result* is a well-formed failure envelope; return its (code, text).

    Checks the three things the contract makes non-negotiable: isError is set,
    the text leads with the code in brackets and nothing before it, and line 1
    is a sentence rather than a symbol.
    """
    assert isinstance(result, CallToolResult), f"a failure must be a CallToolResult, got {type(result)}"
    assert result.isError is True, "a failure must set isError (rule 1)"
    text = result.content[0].text
    match = _CODE_RE.match(text)
    assert match, f"failure text must lead with [code]: {text!r}"
    first_line = text.splitlines()[0]
    assert first_line.endswith("."), f"line 1 must be a sentence: {first_line!r}"
    return match.group(1), text


def failure_code(result) -> str:
    return failure(result)[0]


def failure_text(result) -> str:
    return failure(result)[1]
