"""deadcowboy_mcp.templum -- conditional persistence to the Templum ledger.

When a Templum workspace key is present -- the TEMPLUM_KEY env var, or
the X-Templum-Key header on the HTTP transport -- every drop the caller
authors is POSTed to the ledger as one event. Sweeps are not written;
other agents' drops are not written. The workspace records what this
operator's agents contributed, not what they read.

Fire-and-forget and strictly fail-safe: a Templum outage, a bad key, or
a slow network can never break a drop.

Config (env):

    TEMPLUM_URL  -- default https://api.terradev.cloud/templum/v1
    TEMPLUM_KEY  -- the tpl_ workspace key (stdio / single-tenant)
"""

import atexit
import contextvars
import json
import logging
import os
import threading
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

TEMPLUM_URL = os.environ.get(
    "TEMPLUM_URL", "https://api.terradev.cloud/templum/v1").rstrip("/")
TEMPLUM_KEY = os.environ.get("TEMPLUM_KEY", "").strip() or None

# Per-request key on the HTTP transport -- the hosted server is
# multi-tenant, so the caller's header wins over the env var.
_request_key = contextvars.ContextVar("templum_request_key", default=None)


def set_request_key(key):
    """HTTP transports call this per request with the X-Templum-Key
    header value (or None)."""
    _request_key.set(key)


def workspace_key(explicit=None):
    """Precedence: explicit arg > per-request header > env var."""
    return explicit or _request_key.get() or TEMPLUM_KEY


def emit(event_type, payload, attestation_id=None, key=None):
    """Persist one event to the ledger. Never raises; returns the
    threading.Thread so tests can join it, or None when no key."""
    ws_key = workspace_key(key)
    if not ws_key:
        return None
    body = {
        "primitive": "deadcowboy",
        "event_type": event_type,
        "payload": payload,
        "attestation_id": attestation_id,
    }
    t = threading.Thread(target=_post, args=(ws_key, body), daemon=True)
    _in_flight.add(t)
    t.start()
    return t


# In-flight emits are tracked so a short-lived process can drain them
# at exit instead of dropping the write mid-flight.
_in_flight = set()


@atexit.register
def _drain():
    for t in list(_in_flight):
        t.join(timeout=2.0)


def _post(key, body):
    try:
        req = urllib.request.Request(
            TEMPLUM_URL + "/events",
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3.0):
            pass  # fire and forget -- 2xx is all we need
    except urllib.error.HTTPError as e:
        logger.debug("templum: event rejected: HTTP %s", e.code)
    except Exception as e:
        logger.debug("templum: emit failed: %s", e)
    finally:
        _in_flight.discard(threading.current_thread())
