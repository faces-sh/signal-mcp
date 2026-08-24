"""circuit_buffer: the Python half of the circuit cache (docs/reqs/003_handle_bus.md).

Two functions every MCP server we control calls at its central tool-call handler:
- resolve_args(args): expand any slug token (@@hN@@) in the tool's arguments back into the cached payload,
  BEFORE the tool's own validation. Run at the TOP of a call. An unknown/expired slug raises CircuitError.
- wrap_result(text): if the result is large, park it in the cache and PREPEND its slug, so the slug survives
  the cross-turn step-log head and the next tool can pass it instead of the model retyping the payload.

Config comes from env Maestro injects (MAESTRO_CIRCUIT_URL / _SECRET / MAESTRO_SESSION_ID). When absent (the
server run outside Maestro, e.g. plain npx/CLI), both functions are no-ops so the server still works solo.

The pinned contract (mirrored by the TypeScript helper) lives in fixtures/circuit_vector.json.
"""
import json
import os
import re
import urllib.request
import urllib.error

TOKEN_RE = re.compile(r"@@h\d+@@")
THRESHOLD = 200   # only park results at least this long; smaller ones the model carries fine


class CircuitError(RuntimeError):
    """A slug reference that cannot be resolved (unknown/expired). Fails loud, never silently passes the token."""


def _cfg():
    url = os.environ.get("MAESTRO_CIRCUIT_URL", "").strip()
    secret = os.environ.get("MAESTRO_CIRCUIT_SECRET", "").strip()
    session = os.environ.get("MAESTRO_SESSION_ID", "").strip()
    return (url, secret, session) if (url and secret and session) else None


def _post(path, body, url, secret):
    req = urllib.request.Request(url.rstrip("/") + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "X-Circuit-Secret": secret},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def wrap_result(text):
    cfg = _cfg()
    if not cfg or not isinstance(text, str) or len(text) < THRESHOLD:
        return text
    url, secret, session = cfg
    try:
        slug = _post("/put", {"session": session, "payload": text}, url, secret).get("slug")
    except Exception:
        return text   # best-effort: a buffer hiccup never breaks the tool
    if not slug:
        return text
    tag = ("[circuit " + slug + " · to feed this whole result into another tool, pass " + slug +
           " as its argument instead of retyping it; read_tool_result(" + slug + ") shows it in full later]")
    return tag + "\n\n" + text


def _fetch(slug, url, secret, session):
    try:
        return _post("/get", {"session": session, "slug": slug}, url, secret).get("payload", "")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise CircuitError("Unknown or expired circuit slug " + slug + "; it is no longer cached, re-fetch it.")
        raise


def read_tool_result(slug):
    """The on-demand full read behind the agent-facing `read_tool_result` tool: return the WHOLE cached
    payload for a slug, so the agent can see a prior step's full output when the step-log head wasn't enough.
    Always answers in plain human text (never raises): the payload, or a clear note when the circuit is absent
    or the slug is gone. With scrub-on-eviction a slug the agent can still see is always live, so the gone case
    only arises for a hallucinated or very old reference."""
    token_match = TOKEN_RE.search(slug or "")
    token = token_match.group(0) if token_match else (slug or "").strip()
    if not token:
        return "read_tool_result needs a circuit slug like @@h7@@."
    cfg = _cfg()
    if not cfg:
        return "The circuit cache isn't available here, so I can't reopen " + token + "."
    url, secret, session = cfg
    try:
        return _fetch(token, url, secret, session)
    except CircuitError:
        return "That result (" + token + ") is no longer cached; re-run the step to produce it again."
    except Exception as e:
        return "Couldn't read " + token + ": " + str(e)


def resolve_args(args):
    cfg = _cfg()
    if not cfg:
        return args
    url, secret, session = cfg

    def expand(v):
        if isinstance(v, str) and TOKEN_RE.search(v):
            return TOKEN_RE.sub(lambda m: _fetch(m.group(0), url, secret, session), v)
        if isinstance(v, dict):
            return {k: expand(x) for k, x in v.items()}
        if isinstance(v, list):
            return [expand(x) for x in v]
        return v

    return expand(args)
