"""deadcowboy_mcp.anchor -- publish signed tree heads externally.

A Merkle tree alone proves the log is append-only to anyone watching
it -- but if the operator rewrites the whole tree, only someone who
pinned an earlier head can tell. Anchoring closes that gap: signed
tree heads are periodically published somewhere the operator does not
control, so history cannot be retroactively rewritten.

Backends (DEADCOWBOY_ANCHOR_BACKEND):

- local (default): records the STH in the anchors table. Same database,
  so it deters rather than prevents rewrite -- useful for dev and for
  an audit trail of when heads were committed.
- http: POSTs the STH JSON to DEADCOWBOY_ANCHOR_URL -- any external
  notary: a witness service, a second log, or a relay that writes it
  on-chain.
- evm: sends an EVM transaction carrying the root hash as calldata --
  a real on-chain anchor. Requires `pip install eth_account` plus
  DEADCOWBOY_ANCHOR_RPC and DEADCOWBOY_ANCHOR_KEY (hex private key);
  optional DEADCOWBOY_ANCHOR_TO (defaults to a self-send).

Cadence: anchor when ANCHOR_EVERY new leaves have landed since the last
anchor OR the last anchor is older than ANCHOR_MAX_AGE_S. Publishing
runs on a daemon thread -- ingest never blocks on a notary.
"""

import json
import os
import threading
import time
import urllib.request

ANCHOR_EVERY = int(os.environ.get("DEADCOWBOY_ANCHOR_EVERY", "64"))
ANCHOR_MAX_AGE_S = int(
    os.environ.get("DEADCOWBOY_ANCHOR_MAX_AGE_S", "3600"))
_BACKEND_NAME = os.environ.get("DEADCOWBOY_ANCHOR_BACKEND", "local")

_backend = None
_publish_lock = threading.Lock()


class AnchorError(Exception):
    pass


# ---------------------------------------------------------------------------
# backends
# ---------------------------------------------------------------------------

class LocalAnchor:
    """Records the STH in the anchors table. Proves the operator
    committed to this head at this time, but lives in the same DB --
    configure http or evm for an anchor outside operator control."""
    name = "local"

    def publish(self, sth):
        return {"ref": f"local:{sth['tree_size']}"}


class HTTPAnchor:
    """POSTs the signed tree head to a configured notary endpoint."""
    name = "http"

    def __init__(self):
        self._url = os.environ.get("DEADCOWBOY_ANCHOR_URL")
        if not self._url:
            raise AnchorError("http backend: DEADCOWBOY_ANCHOR_URL "
                              "not set")

    def publish(self, sth):
        req = urllib.request.Request(
            self._url, data=json.dumps(sth).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read().decode()[:512]
        return {"ref": self._url, "detail": {"response": body}}


class EVMAnchor:
    """Anchors the tree head as calldata in an EVM transaction -- the
    root hash lands on-chain, timestamped by the block. Self-send by
    default; set DEADCOWBOY_ANCHOR_TO to write to a contract instead."""
    name = "evm"

    def __init__(self):
        try:
            from eth_account import Account
        except ImportError as e:
            raise AnchorError(
                "evm backend requires eth_account: "
                "pip install eth_account") from e
        self._Account = Account
        self._acct = Account.from_key(os.environ["DEADCOWBOY_ANCHOR_KEY"])
        self._rpc = os.environ["DEADCOWBOY_ANCHOR_RPC"]
        self._to = os.environ.get("DEADCOWBOY_ANCHOR_TO",
                                  self._acct.address)

    def _call(self, method, params):
        req = urllib.request.Request(
            self._rpc,
            data=json.dumps({"jsonrpc": "2.0", "id": 1,
                             "method": method,
                             "params": params}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            out = json.loads(r.read())
        if "error" in out:
            raise AnchorError(f"{method}: {out['error']}")
        return out["result"]

    def publish(self, sth):
        nonce = int(self._call(
            "eth_getTransactionCount",
            [self._acct.address, "pending"]), 16)
        chain = int(self._call("eth_chainId", []), 16)
        gas_price = int(self._call("eth_gasPrice", []), 16)
        tx = {"nonce": nonce, "to": self._to, "value": 0,
              "data": "0x" + sth["root_hash"], "gas": 50000,
              "gasPrice": gas_price, "chainId": chain}
        signed = self._acct.sign_transaction(tx)
        txid = self._call("eth_sendRawTransaction",
                          [signed.rawTransaction.hex()])
        return {"ref": txid,
                "detail": {"chain_id": chain,
                           "address": self._acct.address}}


_BACKENDS = {"local": LocalAnchor, "http": HTTPAnchor, "evm": EVMAnchor}


def _get_backend():
    global _backend
    if _backend is None:
        cls = _BACKENDS.get(_BACKEND_NAME)
        if cls is None:
            raise AnchorError(f"unknown anchor backend "
                              f"{_BACKEND_NAME!r}")
        _backend = cls()
    return _backend


# ---------------------------------------------------------------------------
# cadence + publish
# ---------------------------------------------------------------------------

def maybe_anchor():
    """Called after each log append. Anchors when ANCHOR_EVERY new
    leaves landed since the last successful anchor, or the last anchor
    is older than ANCHOR_MAX_AGE_S. Cheap check synchronously; the
    publish itself runs on a daemon thread."""
    from deadcowboy_mcp import store
    sth = store.log_sth()
    if not sth or sth["tree_size"] == 0:
        return
    last = store.last_anchor()
    if last and last["ref"] is not None:
        if (sth["tree_size"] - last["tree_size"] < ANCHOR_EVERY
                and time.time() - last["anchored_at"]
                < ANCHOR_MAX_AGE_S):
            return
    if not _publish_lock.acquire(blocking=False):
        return
    threading.Thread(target=_publish, args=(sth,), daemon=True).start()


def _publish(sth):
    from deadcowboy_mcp import store
    try:
        backend = _get_backend()
        rec = backend.publish(sth)
        detail = (json.dumps(rec["detail"], sort_keys=True)
                  if rec.get("detail") else None)
        store.locked(store.record_anchor, sth["tree_size"],
                     sth["root_hash"], backend.name, rec.get("ref"),
                     detail)
    except Exception as e:  # anchor failures must never break ingest
        try:
            store.locked(store.record_anchor, sth["tree_size"],
                         sth["root_hash"], _BACKEND_NAME, None,
                         f"error: {e}")
        except Exception:
            pass
    finally:
        _publish_lock.release()
