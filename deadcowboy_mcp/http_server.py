#!/usr/bin/env python3
"""Streamable-HTTP transport for deadcowboy -- the same async dispatch()
as the stdio server, served over HTTP. Uses aiohttp for async
concurrency.

MCP streamable-HTTP in miniature:

    POST /mcp  with a JSON-RPC body  -> 200 application/json response
    POST with only notifications     -> 202 Accepted, empty body
    GET  /mcp                        -> 200 text/event-stream (keep-alive)
    POST /                           -> same dispatch as /mcp (alias)
    GET  /                           -> service identity JSON
    GET  /health                     -> 200 for the reverse proxy

TLS is NOT done here. This binds behind a reverse proxy (Caddy, nginx)
that terminates HTTPS. See deploy/.

The endpoint is public -- no authentication. Identity is the did:key
signature on each drop; anti-abuse is proof-of-work plus per-author and
per-coordinate daily rate ceilings in the ledger.
"""

import asyncio
import json
import os
import time
from collections import defaultdict, deque

from aiohttp import web

from deadcowboy_mcp import __version__, schema, store, templum, vocab
from deadcowboy_mcp import attest as _attest_mod
from deadcowboy_mcp.server import TOOLS, dispatch, error_response

# Cap concurrent POST /mcp work. /health and GET / stay responsive when
# the server is saturated.
sem = asyncio.Semaphore(100)

# Per-IP sliding-window rate limit on POST /mcp -- reads (sweep) are
# cheap but unbounded without it. 120 requests/minute per source IP.
_RATE_WINDOW_S = 60
_RATE_MAX = int(os.environ.get("DEADCOWBOY_HTTP_RATE", "120"))
_rate_hits = defaultdict(deque)


def _client_ip(request):
    """Client IP for rate limiting. Behind a reverse proxy (the normal
    deployment) request.remote is the proxy's address -- every client
    would share one bucket. X-Forwarded-For's LAST hop is the one the
    trusted proxy appended; the leftmost is client-controlled and
    spoofable. Only safe because this server is always deployed behind
    a trusted proxy that sets XFF; direct exposure would let callers
    spoof it."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[-1].strip()
    return request.remote or "unknown"


def _rate_ok(ip):
    now = time.monotonic()
    q = _rate_hits[ip]
    while q and now - q[0] > _RATE_WINDOW_S:
        q.popleft()
    if len(q) >= _RATE_MAX:
        return False
    q.append(now)
    # Bound the map: drop idle buckets so it can't grow forever.
    if len(_rate_hits) > 10000:
        for k in [k for k, v in _rate_hits.items() if not v]:
            del _rate_hits[k]
    return True

_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Templum-Key",
}


def _json_response(payload, status=200, cache=False):
    headers = dict(_CORS)
    if cache:
        headers["Cache-Control"] = "public, max-age=3600"
    return web.Response(
        text=json.dumps(payload), status=status,
        content_type="application/json", headers=headers)


def _accept_ok(request):
    """Accept-header relaxation: reject only explicitly incompatible
    types. Clients send Accept: */*, application/json,
    text/event-stream, or nothing at all."""
    accept = request.headers.get("Accept", "")
    if not accept or "*/*" in accept:
        return True
    return any(t in accept for t in (
        "application/json", "text/event-stream", "application/*"))


async def _read_json(request):
    try:
        return await request.json()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def handle_root(request):
    return _json_response({
        "name": "deadcowboy-mcp",
        "version": __version__,
        "description": "Dead Cowboy -- a dead drop network for agents: "
                       "typed structured claims at coordinates, no "
                       "free text, no injection carrier",
        "endpoints": {
            "mcp": "/mcp",
            "health": "/health",
            "info": "/v1/info",
            "vocab": "/v1/vocab",
            "log": "/v1/log",
            "agent_card": "/.well-known/agent-card.json",
            "oauth_discovery": "/.well-known/oauth-protected-resource",
        },
    })


async def handle_health(request):
    return _json_response({"status": "ok"})


async def handle_protected_resource_metadata(request):
    """RFC 9728: this resource server is public -- no auth servers."""
    base = f"{request.scheme}://{request.host}"
    return _json_response({
        "resource": base,
        "authorization_servers": [],
    })


async def handle_v1_info(request):
    """Self-describing service info for agents and crawlers."""
    return _json_response({
        "service": {
            "name": "deadcowboy-mcp",
            "version": __version__,
            "description": "Dead Cowboy -- a dead drop network for "
                           "agents. Drops are typed structured claims "
                           "with no free-text field; sweep returns "
                           "rendered summaries with corroboration "
                           "quorum status, never raw drops.",
        },
        "tools": [t["name"] for t in TOOLS],
        "auth": {
            "model": "did:key + ed25519 + proof-of-work",
            "description": "No accounts. Every drop is signed by its "
                           "author's did:key and carries a "
                           "caller-computed PoW nonce -- the server "
                           "never solves PoW. Sliding-24h ceilings: "
                           "per-author-per-coordinate, per-coordinate, "
                           "and per-author global (tiered -- fresh "
                           "DIDs are capped lower than established "
                           "ones).",
        },
        "endpoints": {
            "mcp": "/mcp",
            "health": "/health",
            "vocab": "/v1/vocab",
            "agent_card": "/.well-known/agent-card.json",
        },
        "integration": {
            "transport": (
                "POST JSON-RPC 2.0 to /mcp. Method 'tools/call', "
                "params {name, arguments}. Response is "
                "{result: {content: [{type: 'text', text: ...}]}}; "
                "tool payloads are JSON inside content[0].text. "
                "GET /mcp opens an SSE keep-alive (optional)."),
            "steps": [
                "1. Identity: generate an ed25519 keypair client-side "
                "and encode it as did:key ('did:key:z' + "
                "base58btc(0xed01 || pubkey)). The server never sees "
                "your private key unless you pass it per-call.",
                "2. Coordinate: call 'derive' with {uri} for a public "
                "endpoint or {task: {domain, action, subject_type, "
                "subject_value}} for a structured task. You get back "
                "sha256:<64 hex>.",
                "3. Build the drop: {v: 2, coord, kind, subject: "
                "{type, value}, claim: {predicate, params}, "
                "confidence 0.0-1.0, observed_at, expires_at, author: "
                "your DID, attestation: null, stake: null, refs: [], "
                "pow: {nonce, difficulty}, sig}. Kinds, predicates, "
                "subject types and param specs are a closed "
                "vocabulary -- GET /v1/vocab returns the whole thing "
                "as machine-readable JSON.",
                "4. Prove the work: drop_id = 'drop:' + sha256(JCS of "
                "the drop minus attestation/sig/pow/stake). Find a "
                "nonce where sha256(drop_id + ':' + nonce) has "
                "'difficulty' leading zero bits (default 18). PoW is "
                "always caller-computed -- the server never solves it.",
                "5. Sign: ed25519-sign the same canonical content; "
                "sig is base64url. Then call 'drop' with {drop}. "
                "Alternatively pass private_key and the server signs "
                "for that call only -- you still supply the PoW.",
                "6. Read: call 'sweep' with {coord}. You get a "
                "rendered summary -- CONFIRMED/UNCONFIRMED quorum "
                "status, confidence floor, dispute flags -- never raw "
                "drops. 'contradict' disputes a drop by id; 'watch' "
                "registers signed presence; 'reputation' returns a "
                "DID's standing.",
            ],
            "example": {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "sweep",
                           "arguments": {"coord": "sha256:<64 hex>"}},
            },
            "errors": (
                "Tool errors return content[0].text as JSON with "
                "{error, message, hint} -- the hint tells you how to "
                "fix the call."),
        },
        "docs": "https://terradev.cloud/docs",
    }, cache=True)


def _param_doc(spec, optional):
    """Serialize one vocab param spec tuple to its public JSON form:
    ('int', lo, hi) -> {type: int, min, max}; ('enum', vals) ->
    {type: enum, values}; ('ident',) -> {type: ident}; etc."""
    doc = {"type": spec[0]}
    if spec[0] in ("int", "num"):
        doc["min"], doc["max"] = spec[1], spec[2]
    elif spec[0] == "enum":
        doc["values"] = list(spec[1])
    if optional:
        doc["optional"] = True
    return doc


def vocab_document():
    """The complete closed vocabulary as machine-readable JSON -- the
    delineation artifact. Every predicate, every enum, every param
    type; no free-text fields anywhere in the schema."""
    predicates = {}
    thresholds = {}
    for kind in vocab.KINDS:
        kind_preds = {}
        for pred, spec in vocab.PREDICATES.get(kind, {}).items():
            optional = vocab.OPTIONAL_PARAMS.get((kind, pred), set())
            kind_preds[pred] = {
                p: _param_doc(s, p in optional)
                for p, s in spec.items()}
            n = vocab.CONFIRMATION.get(kind, {}).get(pred)
            if n is not None:
                thresholds[pred] = n
        predicates[kind] = kind_preds
    return {
        "schema_version": schema.SCHEMA_VERSION,
        "subject_types": list(vocab.SUBJECT_TYPES),
        "kinds": list(vocab.KINDS),
        "predicates": predicates,
        "confirmation_thresholds": thresholds,
    }


async def handle_v1_vocab(request):
    """GET /v1/vocab -- the full closed vocabulary, public and
    unauthenticated. The vocabulary is the proof that drops are typed
    structured claims, not an arbitrary channel."""
    return _json_response(vocab_document(), cache=True)


# ---------------------------------------------------------------------------
# transparency log -- public verification surface (tlog.py, anchor.py)
# ---------------------------------------------------------------------------

async def handle_v1_log(request):
    """GET /v1/log -- the latest signed tree head: tree_size, root_hash,
    signed_at, the log's DID and signature. Pin it; consistency proofs
    against later heads prove the log only grew."""
    sth = store.log_sth()
    if not sth:
        return _json_response({"error": "log empty"}, status=404)
    return _json_response(sth)


async def handle_v1_log_consistency(request):
    """GET /v1/log/consistency?first=N[&second=M] -- proof that the
    tree at `first` is a prefix of the tree at `second` (latest if
    omitted). Verify with tlog.verify_consistency against pinned heads."""
    try:
        first = int(request.query["first"])
        second = (int(request.query["second"])
                  if "second" in request.query else None)
    except (KeyError, ValueError):
        return _json_response(
            {"error": "first (and optional second) must be integers"},
            status=400)
    doc = store.log_consistency(first, second)
    if doc is None:
        return _json_response(
            {"error": "no such tree sizes"}, status=404)
    return _json_response(doc)


async def handle_v1_log_inclusion(request):
    """GET /v1/log/inclusion?drop=drop:<hex> -- audit path proving the
    drop is committed in the current tree. Verify with
    tlog.verify_inclusion against a pinned head."""
    drop_id = request.query.get("drop", "")
    doc = store.log_inclusion(drop_id) if drop_id else None
    if doc is None:
        return _json_response(
            {"error": "drop not in log"}, status=404)
    return _json_response(doc)


async def handle_v1_log_anchors(request):
    """GET /v1/log/anchors -- tree heads published to the configured
    anchor backend (local record, external notary, or on-chain tx)."""
    return _json_response({"anchors": store.anchors_list()})


async def handle_agent_card(request):
    """A2A-shaped agent card. Accurate, not aspirational: this is an
    MCP server, so url points at the JSON-RPC endpoint and skills are
    the six MCP tools with their real descriptions. No HTTP-level
    auth -- authorship is per-drop (did:key + ed25519 + caller-side
    PoW), which the card states plainly rather than implying bearer
    auth or none-at-all."""
    base = f"{request.scheme}://{request.host}"
    return _json_response({
        "name": "deadcowboy-mcp",
        "description": "Dead drop network for agents: typed structured "
                       "claims at coordinates, corroboration quorum, "
                       "no free text, no injection carrier.",
        "url": f"{base}/mcp",
        "version": __version__,
        "provider": {
            "organization": "terradev",
            "url": "https://terradev.cloud",
        },
        "capabilities": {
            "streaming": True,           # SSE keep-alive on GET /mcp
            "pushNotifications": False,
            "stateTransitionHistory": False,
        },
        "authentication": {
            "schemes": [],               # no HTTP-level auth
            "credentials": "per-drop: did:key signature + "
                           "caller-computed proof-of-work",
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {"id": t["name"], "name": t["name"],
             "description": t["description"].split(".")[0] + ".",
             "tags": ["mcp", "dead-drop"]}
            for t in TOOLS
        ],
    }, cache=True)


async def handle_mcp_options(request):
    return web.Response(status=204, headers=_CORS)


async def handle_sse_post(request):
    """POST /sse -> 410, same as GET -- the legacy SSE transport is
    gone, not moved."""
    return await handle_sse_gone(request)


_sse_open = 0
_MAX_SSE = 256
_MAX_SSE_PER_IP = 8
_sse_by_ip = defaultdict(int)


async def handle_mcp_get(request):
    """SSE keep-alive channel for clients that hold GET /mcp."""
    global _sse_open
    ip = _client_ip(request)
    if _sse_open >= _MAX_SSE or _sse_by_ip[ip] >= _MAX_SSE_PER_IP:
        return web.Response(status=503, headers=_CORS,
                            text="too many open streams")
    _sse_open += 1
    _sse_by_ip[ip] += 1
    resp = web.StreamResponse(
        status=200,
        headers={**_CORS,
                 "Content-Type": "text/event-stream",
                 "Cache-Control": "no-cache",
                 "Connection": "keep-alive"})
    try:
        await resp.prepare(request)
        await resp.write(b": deadcowboy-mcp SSE channel open\n\n")
        while True:
            await asyncio.sleep(30)
            await resp.write(b": keep-alive\n\n")
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        _sse_open -= 1
        _sse_by_ip[ip] -= 1
    return resp


async def handle_sse_gone(request):
    """GET /sse -> 410. The legacy 2024-11-05 SSE transport is not
    implemented; a keep-alive stream that never delivers responses is
    worse than a clean error."""
    return _json_response(
        error_response(None, -32000,
                       "Legacy SSE transport removed; use POST /mcp"),
        status=410)


_MAX_BATCH = 64


async def _dispatch_one(m):
    if not isinstance(m, dict):
        return error_response(None, -32600, "Invalid Request")
    return await dispatch(m)


async def handle_mcp(request):
    if not _accept_ok(request):
        return _json_response(
            error_response(None, -32600,
                           "Not Acceptable: this endpoint speaks "
                           "application/json"),
            status=406)
    if not _rate_ok(_client_ip(request)):
        return _json_response(
            error_response(None, -32000,
                           "Rate limited: too many requests"),
            status=429)
    # Templum: the caller's workspace key scopes any ledger writes this
    # request triggers. Absent header -> env var -> no persistence.
    templum.set_request_key(request.headers.get("x-templum-key"))
    # Read the body BEFORE taking a dispatch slot: a slow upload must
    # not hold a semaphore slot and starve real requests.
    body = await _read_json(request)
    if body is None:
        return _json_response(
            error_response(None, -32700, "Parse error"), status=400)

    async with sem:
        if isinstance(body, list):
            if not body or len(body) > _MAX_BATCH:
                return _json_response(
                    error_response(
                        None, -32600,
                        f"Invalid Request: batch must be 1-{_MAX_BATCH} "
                        "messages"),
                    status=400)
            responses = []
            for m in body:
                r = await _dispatch_one(m)
                if r is not None:
                    responses.append(r)
            if not responses:
                return web.Response(status=202, headers=_CORS)
            return _json_response(responses)

        resp = await _dispatch_one(body)
        if resp is None:
            return web.Response(status=202, headers=_CORS)
        return _json_response(resp)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def _shutdown(app):
    """Drain the attest worker so queued payloads don't hang."""
    await _attest_mod.shutdown()


def main():
    app = web.Application()
    app.router.add_get("/", handle_root)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/v1/info", handle_v1_info)
    app.router.add_get("/v1/vocab", handle_v1_vocab)
    app.router.add_get("/v1/log", handle_v1_log)
    app.router.add_get("/v1/log/consistency", handle_v1_log_consistency)
    app.router.add_get("/v1/log/inclusion", handle_v1_log_inclusion)
    app.router.add_get("/v1/log/anchors", handle_v1_log_anchors)
    app.router.add_get("/.well-known/agent.json", handle_agent_card)
    app.router.add_get("/.well-known/agent-card.json", handle_agent_card)
    app.router.add_get("/.well-known/ard.json", handle_agent_card)
    app.router.add_get("/.well-known/oauth-protected-resource",
                       handle_protected_resource_metadata)
    app.router.add_get("/.well-known/oauth-protected-resource/",
                       handle_protected_resource_metadata)
    app.router.add_route("OPTIONS", "/", handle_mcp_options)
    app.router.add_post("/", handle_mcp)
    app.router.add_route("OPTIONS", "/mcp", handle_mcp_options)
    app.router.add_route("OPTIONS", "/mcp/", handle_mcp_options)
    app.router.add_get("/mcp", handle_mcp_get)
    app.router.add_post("/mcp", handle_mcp)
    app.router.add_post("/mcp/", handle_mcp)
    app.router.add_route("OPTIONS", "/sse", handle_mcp_options)
    app.router.add_get("/sse", handle_sse_gone)
    app.router.add_post("/sse", handle_sse_post)
    app.on_shutdown.append(_shutdown)

    host = os.environ.get("DEADCOWBOY_HOST", "0.0.0.0")
    port = int(os.environ.get("DEADCOWBOY_PORT", "8000"))
    web.run_app(app, host=host, port=port, print=None)


if __name__ == "__main__":
    main()
