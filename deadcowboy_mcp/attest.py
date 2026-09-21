"""deadcowboy_mcp.attest -- Stamp attestation for every accepted drop.

Same pattern as quorum: N concurrent tool calls coalesce onto ONE NTP
sample per drain batch; each event still gets its own record (unique
id, own payload hash) built from the shared sample. Throughput stops
being bound by NTP round-trips.

The record shape is identical to stamp-mcp's attest() output, so
`stamp verify` validates it. NTP unreachable -> local-clock fallback,
disclosed in the record -- the disclosure itself is tamper-evident.
"""

import asyncio
import hashlib
import uuid
from datetime import datetime, timezone

try:
    from stamp_mcp.server import (
        query_time as _stamp_query_time,
        _canonical as _stamp_canonical)
except ImportError:  # pragma: no cover
    _stamp_query_time = None
    import json

    def _stamp_canonical(obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))

NTP_SERVER = "time.cloudflare.com"

_attest_q = None
_attest_worker = None
_attest_loop = None


class AttestError(Exception):
    pass


def _stamp_sample(server):
    ntp = _stamp_query_time(server)
    return {"attested_at": ntp["utc"], "time_source": "ntp",
            "time_server": ntp["server"],
            "clock_offset_ms": ntp["offset_ms"]}


def _stamp_record(payload, sample):
    record = {"id": str(uuid.uuid4()), **sample, "payload": payload}
    record["sha256"] = hashlib.sha256(
        _stamp_canonical(record).encode()).hexdigest()
    return record


async def _attest_drain(q):
    while True:
        payload, fut = await q.get()
        batch = [(payload, fut)]
        while True:
            try:
                batch.append(q.get_nowait())
            except asyncio.QueueEmpty:
                break
        try:
            sample = await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(
                    None, _stamp_sample, NTP_SERVER),
                timeout=15.0)
        except Exception:
            sample = {
                "attested_at": datetime.now(timezone.utc).isoformat(),
                "time_source": "local",
            }
        for payload, fut in batch:
            try:
                fut.set_result(_stamp_record(payload, sample))
            except Exception as e:
                if not fut.done():
                    fut.set_exception(e)


def _attest_queue():
    global _attest_q, _attest_worker, _attest_loop
    loop = asyncio.get_running_loop()
    if _attest_q is None or _attest_loop is not loop:
        _attest_q = asyncio.Queue()
        _attest_worker = None
        _attest_loop = loop
    if _attest_worker is None or _attest_worker.done():
        _attest_worker = asyncio.ensure_future(_attest_drain(_attest_q))
    return _attest_q


async def attest(payload):
    """Attest a payload; returns the Stamp record. Raises AttestError
    if stamp-mcp is missing or the worker stalls."""
    if _stamp_query_time is None:
        raise AttestError("stamp-mcp is not installed; cannot attest")
    fut = asyncio.get_running_loop().create_future()
    _attest_queue().put_nowait((payload, fut))
    try:
        return await asyncio.wait_for(asyncio.shield(fut), 30)
    except asyncio.TimeoutError:
        raise AttestError("attestation did not complete within 30s")


async def shutdown():
    """Cancel the drain worker and fail any queued futures -- without
    this, queued attest() callers hang until their 30s timeout on
    server shutdown."""
    global _attest_worker
    if _attest_worker is not None and not _attest_worker.done():
        _attest_worker.cancel()
        try:
            await _attest_worker
        except asyncio.CancelledError:
            pass
    _attest_worker = None
    if _attest_q is not None:
        while True:
            try:
                _payload, fut = _attest_q.get_nowait()
            except asyncio.QueueEmpty:
                break
            if not fut.done():
                fut.set_exception(AttestError("server shutting down"))
