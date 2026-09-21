"""deadcowboy_mcp.store -- the drop ledger.

SQLite, WAL mode, one file (default ~/.deadcowboy/drops.db, override
DEADCOWBOY_DB). Drops are immutable: no UPDATE, no DELETE except the
expiry sweeper. No deletion means an author cannot poison a coordinate
and clean up -- every drop stands on the record until it expires.

Tables:

    drops        one row per validated drop, keyed by drop id
    watchers     (coord, author) presence registrations
    authors      per-DID counters for the reputation view
    rate_events  (ts, author, coord) -- one row per accepted drop;
                 rate limits count these, NOT live drops, so a
                 short-TTL drop can't evade the window by expiring
"""

import json
import os
import sqlite3
import threading
import time

DB_PATH = os.environ.get(
    "DEADCOWBOY_DB", os.path.expanduser("~/.deadcowboy/drops.db"))

# Rate ceilings (sliding 24h windows). Env-overridable.
MAX_DROPS_PER_AUTHOR_COORD_DAY = int(
    os.environ.get("DEADCOWBOY_AUTHOR_COORD_RATE", "8"))
MAX_DROPS_PER_COORD_DAY = int(
    os.environ.get("DEADCOWBOY_COORD_RATE", "64"))
# Per-author global cap, tiered by standing: a DID keypair is cheap to
# mint, so a fresh DID must not drop at the same rate as one with
# history. New = first_seen < 7 days AND < 32 published drops.
MAX_DROPS_PER_AUTHOR_DAY_NEW = int(
    os.environ.get("DEADCOWBOY_AUTHOR_RATE_NEW", "32"))
MAX_DROPS_PER_AUTHOR_DAY_EST = int(
    os.environ.get("DEADCOWBOY_AUTHOR_RATE_EST", "256"))
_AUTHOR_NEW_AGE_S = 7 * 86400
_AUTHOR_NEW_DROPS = 32
MAX_WATCHERS_PER_COORD = int(
    os.environ.get("DEADCOWBOY_MAX_WATCHERS", "1024"))
MAX_WATCHES_PER_AUTHOR = int(
    os.environ.get("DEADCOWBOY_MAX_WATCHES_PER_AUTHOR", "256"))
MAX_DROPS_TOTAL = int(
    os.environ.get("DEADCOWBOY_MAX_DROPS", "1000000"))
# Presence decays: a watcher registration is fresh for 30 days, then
# stops counting. Re-watching refreshes it.
WATCHER_TTL_S = int(
    os.environ.get("DEADCOWBOY_WATCHER_TTL_S", str(30 * 86400)))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS drops (
    id           TEXT PRIMARY KEY,
    coord        TEXT NOT NULL,
    kind         TEXT NOT NULL,
    predicate    TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    author       TEXT NOT NULL,
    confidence   REAL NOT NULL,
    observed_at  TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    body         TEXT NOT NULL,          -- canonical drop JSON
    attestation  TEXT,
    created_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_drops_coord ON drops(coord, expires_at);
CREATE INDEX IF NOT EXISTS idx_drops_author ON drops(author);
CREATE INDEX IF NOT EXISTS idx_drops_pred
    ON drops(coord, kind, predicate);

CREATE TABLE IF NOT EXISTS watchers (
    coord      TEXT NOT NULL,
    author     TEXT NOT NULL,
    last_seen  REAL NOT NULL,
    PRIMARY KEY (coord, author)
);

CREATE TABLE IF NOT EXISTS authors (
    did                      TEXT PRIMARY KEY,
    first_seen               REAL NOT NULL,
    drops_published          INTEGER NOT NULL DEFAULT 0,
    contradictions_received  INTEGER NOT NULL DEFAULT 0,
    contradictions_raised    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rate_events (
    ts     REAL NOT NULL,
    author TEXT NOT NULL,
    coord  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_ts ON rate_events(ts);

-- Transparency log: append-only Merkle tree over drop ids (tlog.py).
-- Leaves are never updated or deleted -- expired drops stay in the
-- tree; the leaf proves the drop WAS in the ledger. One signed tree
-- head per append; anchors record heads published externally.
CREATE TABLE IF NOT EXISTS tlog_leaves (
    leaf_index INTEGER PRIMARY KEY,
    drop_id    TEXT NOT NULL UNIQUE,
    leaf_hash  TEXT NOT NULL           -- hex sha256(0x00 || drop_id)
);
CREATE TABLE IF NOT EXISTS tlog_heads (
    tree_size  INTEGER PRIMARY KEY,
    root_hash  TEXT NOT NULL,
    signed_at  REAL NOT NULL,
    signature  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS anchors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_size   INTEGER NOT NULL,
    root_hash   TEXT NOT NULL,
    backend     TEXT NOT NULL,
    ref         TEXT,
    anchored_at REAL NOT NULL,
    detail      TEXT
);
"""

_lock = threading.Lock()
_conn = None
_conn_path = None


def _connect():
    global _conn, _conn_path
    if _conn is not None and _conn_path == DB_PATH:
        return _conn
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA synchronous=NORMAL")
    _conn.executescript(_SCHEMA)
    _conn_path = DB_PATH
    _tlog_backfill(_conn)
    return _conn


class StoreError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# rate limits -- counted in the ledger so they survive restarts
# ---------------------------------------------------------------------------

def _author_cap(author, ts):
    """Per-author global ceiling, tiered by standing. A fresh DID --
    first_seen < 7 days AND < 32 published drops -- gets the low cap;
    an established one gets the high cap. Reputation has to be earned
    before it buys throughput."""
    row = _connect().execute(
        "SELECT first_seen, drops_published FROM authors WHERE did=?",
        (author,)).fetchone()
    if row is None:
        return MAX_DROPS_PER_AUTHOR_DAY_NEW
    if (ts - row["first_seen"] < _AUTHOR_NEW_AGE_S
            and row["drops_published"] < _AUTHOR_NEW_DROPS):
        return MAX_DROPS_PER_AUTHOR_DAY_NEW
    return MAX_DROPS_PER_AUTHOR_DAY_EST


def claim_rate_slot(author, coord, now=None):
    """Check the sliding-24h ceilings AND record the attempt in one
    locked step. Counts rate_events -- not live drops -- so a
    short-TTL drop can't evade the window by expiring. Claiming the
    slot BEFORE attestation means a rejected drop never mints an
    orphan Stamp record; a consumed slot on a later-failing insert is
    acceptable (the attempt still cost the author budget).

    Three ceilings: per-author-per-coord, per-coord, and per-author
    global (tiered -- fresh DIDs get less than established ones)."""
    ts = now or time.time()
    cutoff = ts - 86400
    conn = _connect()
    n = conn.execute(
        "SELECT COUNT(*) c FROM rate_events WHERE author=? AND coord=? "
        "AND ts>?", (author, coord, cutoff)).fetchone()["c"]
    if n >= MAX_DROPS_PER_AUTHOR_COORD_DAY:
        raise StoreError(
            "rate_limited",
            f"author exceeded {MAX_DROPS_PER_AUTHOR_COORD_DAY} "
            "drops/24h at this coordinate")
    n = conn.execute(
        "SELECT COUNT(*) c FROM rate_events WHERE coord=? AND ts>?",
        (coord, cutoff)).fetchone()["c"]
    if n >= MAX_DROPS_PER_COORD_DAY:
        raise StoreError(
            "coord_saturated",
            f"coordinate saturated: {MAX_DROPS_PER_COORD_DAY} "
            "drops/24h from all authors")
    cap = _author_cap(author, ts)
    n = conn.execute(
        "SELECT COUNT(*) c FROM rate_events WHERE author=? AND ts>?",
        (author, cutoff)).fetchone()["c"]
    if n >= cap:
        raise StoreError(
            "rate_limited",
            f"author exceeded {cap} drops/24h globally "
            "(fresh DIDs are capped lower until they accumulate "
            "history)")
    conn.execute(
        "INSERT INTO rate_events (ts, author, coord) VALUES (?,?,?)",
        (ts, author, coord))
    conn.commit()


# ---------------------------------------------------------------------------
# drops
# ---------------------------------------------------------------------------

def insert_drop(drop_id, drop, attestation_id, now=None):
    """Store a validated drop. Caller has already claimed a rate slot
    under the store lock. Returns the row id.

    Recomputes the drop id from the body as defense-in-depth: a
    caller-supplied id that doesn't match the content is a bug, not a
    drop."""
    from deadcowboy_mcp import identity, schema
    if identity.drop_id(schema.signed_content(drop)) != drop_id:
        raise StoreError("id_mismatch",
                         "drop id does not match signed content")
    conn = _connect()
    purge_expired(now)  # throttled internally; expired rows never linger
    try:
        conn.execute(
            "INSERT INTO drops (id, coord, kind, predicate, "
            "subject_type, author, confidence, observed_at, expires_at, "
            "body, attestation, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (drop_id, drop["coord"], drop["kind"],
             drop["claim"]["predicate"], drop["subject"]["type"],
             drop["author"], drop["confidence"], drop["observed_at"],
             drop["expires_at"], json.dumps(drop, sort_keys=True,
                                            separators=(",", ":")),
             attestation_id, now or time.time()))
    except sqlite3.IntegrityError:
        raise StoreError("duplicate", "drop id already exists")
    conn.execute(
        "INSERT INTO authors (did, first_seen, drops_published) "
        "VALUES (?,?,1) "
        "ON CONFLICT(did) DO UPDATE SET "
        "drops_published=drops_published+1",
        (drop["author"], now or time.time()))
    _tlog_append(conn, drop_id)
    conn.commit()
    from deadcowboy_mcp import anchor
    anchor.maybe_anchor()
    return drop_id


def get_drop(drop_id):
    row = _connect().execute(
        "SELECT * FROM drops WHERE id=?", (drop_id,)).fetchone()
    return dict(row) if row else None


SWEEP_LIMIT = 256


def drops_at(coord, kinds=None, min_confidence=0.0, now=None):
    """Live (unexpired) drops at a coordinate, newest first.
    Returns (rows, truncated) -- truncated is True when the coordinate
    holds more live drops than SWEEP_LIMIT, so the renderer can say so
    instead of silently dropping claims from view. An explicitly empty
    kinds list matches nothing."""
    if kinds is not None and not kinds:
        return [], False
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime(now or time.time()))
    # min_confidence filters claims, not disputes -- a low-confidence
    # 'disputes' drop must still surface the CONTRADICTED flag.
    # Corroborations are claims like any other and ARE filtered.
    q = ("SELECT * FROM drops WHERE coord=? AND expires_at>? "
         "AND (confidence>=? OR predicate='disputes')")
    args = [coord, now_iso, min_confidence]
    if kinds:
        q += " AND kind IN (%s)" % ",".join("?" * len(kinds))
        args += list(kinds)
    q += f" ORDER BY created_at DESC LIMIT {SWEEP_LIMIT + 1}"
    rows = [dict(r) for r in _connect().execute(q, args).fetchall()]
    truncated = len(rows) > SWEEP_LIMIT
    rows = rows[:SWEEP_LIMIT]
    # Read-side enforcement: stored data is untrusted input. Every row
    # is re-validated structurally, and the indexed columns must agree
    # with the body -- a row whose body disagrees with its columns is
    # tampered, not a drop.
    return [r for r in rows if _row_sane(r)], truncated


def _row_sane(row):
    """Re-validate a stored row: body parses, passes structural
    validation, and agrees with the indexed columns."""
    from deadcowboy_mcp import schema
    try:
        body = json.loads(row["body"])
    except (TypeError, json.JSONDecodeError):
        return False
    v = schema.validate_stored(body)
    if v is None:
        return False
    return (v["kind"] == row["kind"]
            and v["claim"]["predicate"] == row["predicate"]
            and v["author"] == row["author"]
            and v["coord"] == row["coord"]
            and v["subject"]["type"] == row["subject_type"]
            and v["observed_at"] == row["observed_at"]
            and v["expires_at"] == row["expires_at"])


def count_by_authors(rows):
    """Distinct-author count over a set of drop rows."""
    return len({r["author"] for r in rows})


def record_contradiction(target_drop_id):
    """Bump contradictions_received on the disputed drop's author.
    'Sustained' is computed live at reputation time -- corroboration
    evolves after the contradiction lands, so it is never stored."""
    target = get_drop(target_drop_id)
    if not target:
        return
    conn = _connect()
    conn.execute(
        "INSERT INTO authors (did, first_seen, contradictions_received) "
        "VALUES (?,?,1) ON CONFLICT(did) DO UPDATE SET "
        "contradictions_received=contradictions_received+1",
        (target["author"], time.time()))
    conn.commit()


def record_contradiction_raised(author):
    conn = _connect()
    conn.execute(
        "INSERT INTO authors (did, first_seen, contradictions_raised) "
        "VALUES (?,?,1) ON CONFLICT(did) DO UPDATE SET "
        "contradictions_raised=contradictions_raised+1",
        (author, time.time()))
    conn.commit()


# ---------------------------------------------------------------------------
# watchers
# ---------------------------------------------------------------------------

def add_watcher(coord, author):
    conn = _connect()
    # A re-watch refreshes an existing slot -- it must not count
    # against the cap.
    exists = conn.execute(
        "SELECT 1 FROM watchers WHERE coord=? AND author=?",
        (coord, author)).fetchone()
    if not exists:
        n = watcher_count(coord)
        if n >= MAX_WATCHERS_PER_COORD:
            raise StoreError("watchers_full",
                             "coordinate watcher cap reached")
    mine = conn.execute(
        "SELECT COUNT(*) c FROM watchers WHERE author=? AND last_seen>?",
        (author, time.time() - WATCHER_TTL_S)).fetchone()["c"]
    if mine >= MAX_WATCHES_PER_AUTHOR:
        raise StoreError("watcher_limit",
                         f"author already watches "
                         f"{MAX_WATCHES_PER_AUTHOR} coordinates")
    # Upsert refreshes last_seen -- presence decays after WATCHER_TTL_S.
    conn.execute(
        "INSERT INTO watchers (coord, author, last_seen) VALUES (?,?,?) "
        "ON CONFLICT(coord,author) DO UPDATE SET last_seen=excluded.last_seen",
        (coord, author, time.time()))
    conn.commit()
    return watcher_count(coord)


def watcher_count(coord, now=None):
    """Live watchers only -- registrations older than WATCHER_TTL_S
    don't count."""
    cutoff = (now or time.time()) - WATCHER_TTL_S
    return _connect().execute(
        "SELECT COUNT(*) c FROM watchers WHERE coord=? AND last_seen>?",
        (coord, cutoff)).fetchone()["c"]


# ---------------------------------------------------------------------------
# reputation
# ---------------------------------------------------------------------------

def corroborated_drop_count(author):
    """How many of `author`'s drops were corroborated by at least one
    OTHER DID -- the second leg of the confirmation eligibility floor.
    Counts historical corroborations, expired or live: eligibility is
    about what the identity has earned, not what is currently visible.
    Self-corroboration never counts."""
    conn = _connect()
    own = {r["id"] for r in conn.execute(
        "SELECT id FROM drops WHERE author=?", (author,))}
    if not own:
        return 0
    hits = set()
    for r in conn.execute(
            "SELECT author, body FROM drops WHERE kind='contradiction' "
            "AND predicate='corroborates'"):
        if r["author"] == author:
            continue
        try:
            target = json.loads(r["body"])["claim"]["params"]["target"]
        except (KeyError, TypeError, json.JSONDecodeError):
            continue
        if target in own:
            hits.add(target)
    return len(hits)


def author_stats(did):
    row = _connect().execute(
        "SELECT * FROM authors WHERE did=?", (did,)).fetchone()
    if not row:
        return None
    stats = dict(row)
    stats["corroborated_drops"] = corroborated_drop_count(did)
    return stats


# ---------------------------------------------------------------------------
# maintenance
# ---------------------------------------------------------------------------

_last_purge = 0.0
_PURGE_INTERVAL_S = 60


def purge_expired(now=None):
    """Delete expired drops, stale watchers, and old rate events. The
    only deletion the ledger permits -- expiry, never retraction.
    Throttled to once a minute: callers invoke it on every sweep and
    insert, but a full-table DELETE per call would be O(n) overhead."""
    global _last_purge
    ts = now or time.time()
    if ts - _last_purge < _PURGE_INTERVAL_S:
        return 0
    _last_purge = ts
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
    conn = _connect()
    cur = conn.execute("DELETE FROM drops WHERE expires_at<?", (now_iso,))
    conn.execute("DELETE FROM watchers WHERE last_seen<?",
                 (ts - WATCHER_TTL_S,))
    conn.execute("DELETE FROM rate_events WHERE ts<?", (ts - 2 * 86400,))
    conn.commit()
    return cur.rowcount


def drop_count():
    return _connect().execute("SELECT COUNT(*) c FROM drops").fetchone()["c"]


# ---------------------------------------------------------------------------
# transparency log -- append-only Merkle tree over drop ids (tlog.py)
# ---------------------------------------------------------------------------

def _tlog_append(conn, drop_id):
    """Append drop_id as a leaf and sign a new tree head. Runs inside
    the drop insert's transaction -- the drop and its leaf are one
    atomic write."""
    from deadcowboy_mcp import tlog
    idx = conn.execute(
        "SELECT COUNT(*) c FROM tlog_leaves").fetchone()["c"]
    conn.execute(
        "INSERT INTO tlog_leaves (leaf_index, drop_id, leaf_hash) "
        "VALUES (?,?,?)",
        (idx, drop_id, tlog.leaf_hash(drop_id.encode()).hex()))
    root = tlog.mth(_log_hashes(conn)).hex()
    sth = tlog.sign_sth(idx + 1, root)
    conn.execute(
        "INSERT INTO tlog_heads (tree_size, root_hash, signed_at, "
        "signature) VALUES (?,?,?,?)",
        (sth["tree_size"], sth["root_hash"], sth["signed_at"],
         sth["signature"]))


def _tlog_backfill(conn):
    """Commit pre-log history into the tree: if the log is empty but
    drops exist, append them in insertion order. Runs once per process
    (guarded by the _conn short-circuit). O(n^2) root recomputation --
    fine at ledger scale, and one-time."""
    if conn.execute(
            "SELECT COUNT(*) c FROM tlog_leaves").fetchone()["c"]:
        return
    rows = conn.execute(
        "SELECT id FROM drops ORDER BY created_at, id").fetchall()
    for r in rows:
        _tlog_append(conn, r["id"])
    conn.commit()


def _log_hashes(conn=None):
    conn = conn or _connect()
    return [bytes.fromhex(r["leaf_hash"]) for r in conn.execute(
        "SELECT leaf_hash FROM tlog_leaves ORDER BY leaf_index")]


def log_size():
    return _connect().execute(
        "SELECT COUNT(*) c FROM tlog_leaves").fetchone()["c"]


def log_sth(size=None):
    """The signed tree head at `size` (latest if None), with the log's
    DID attached for verification."""
    conn = _connect()
    if size is None:
        row = conn.execute(
            "SELECT * FROM tlog_heads ORDER BY tree_size DESC "
            "LIMIT 1").fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM tlog_heads WHERE tree_size=?",
            (size,)).fetchone()
    if not row:
        return None
    from deadcowboy_mcp import tlog
    sth = dict(row)
    sth["log_did"] = tlog.log_did()
    return sth


def log_leaf(drop_id):
    row = _connect().execute(
        "SELECT * FROM tlog_leaves WHERE drop_id=?",
        (drop_id,)).fetchone()
    return dict(row) if row else None


def log_inclusion(drop_id):
    """Inclusion proof for a drop at the current tree size."""
    leaf = log_leaf(drop_id)
    if not leaf:
        return None
    from deadcowboy_mcp import tlog
    hashes = _log_hashes()
    path = tlog.inclusion_path(hashes, leaf["leaf_index"])
    return {"drop_id": drop_id, "leaf_index": leaf["leaf_index"],
            "tree_size": len(hashes), "leaf_hash": leaf["leaf_hash"],
            "proof": [p.hex() for p in path]}


def log_consistency(first, second=None):
    """Consistency proof: the tree at `first` is a prefix of the tree
    at `second` (latest if None). Both root hashes included so a
    verifier can check the proof against heads it pinned."""
    from deadcowboy_mcp import tlog
    hashes = _log_hashes()
    second = second or len(hashes)
    if first < 1 or first > second or second > len(hashes):
        return None
    proof = tlog.consistency_proof(hashes[:second], first)
    return {"first": first, "second": second,
            "first_hash": tlog.mth(hashes[:first]).hex(),
            "second_hash": tlog.mth(hashes[:second]).hex(),
            "proof": [p.hex() for p in proof]}


def record_anchor(tree_size, root_hash, backend, ref, detail=None):
    conn = _connect()
    conn.execute(
        "INSERT INTO anchors (tree_size, root_hash, backend, ref, "
        "anchored_at, detail) VALUES (?,?,?,?,?,?)",
        (tree_size, root_hash, backend, ref, time.time(), detail))
    conn.commit()


def last_anchor():
    row = _connect().execute(
        "SELECT * FROM anchors ORDER BY id DESC LIMIT 1").fetchone()
    return dict(row) if row else None


def anchors_list(limit=50):
    return [dict(r) for r in _connect().execute(
        "SELECT * FROM anchors ORDER BY id DESC LIMIT ?", (limit,))]


def locked(fn, *args, **kwargs):
    """Run fn under the global store lock (check-then-insert atomicity)."""
    with _lock:
        return fn(*args, **kwargs)
