"""deadcowboy_mcp.schema -- the drop contract.

A drop is a JSON object conforming to a strict schema. Every field is an
enum from a fixed vocabulary, a number, a boolean, a URL, a hash, an ISO
timestamp, or a bounded identifier string matching a restrictive regex.
There is no message field, no notes field, no description field.

Anything failing validation is rejected at ingest with a structured
error. Nothing partially valid is stored.
"""

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from deadcowboy_mcp import vocab

SCHEMA_VERSION = 2

# Bounds from the work order.
MAX_OBSERVED_AGE_DAYS = 30
MAX_TTL_DAYS = 90
MAX_REFS = 8
MAX_SUBJECT_VALUE = 512
MAX_PARAM_KEYS = 8

_COORD_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DROPREF_RE = re.compile(r"^drop:[0-9a-f]{64}$")
_IDENT_RE = re.compile(r"^[a-z0-9_.:/@-]{1,128}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# ed25519 did:key = 'did:key:z' + base58btc(0xed01 || 32-byte pubkey)
# = 34 bytes -> exactly 46-48 base58 chars. Tighter than a generic
# did:key shape so bad DIDs fail here, not later in did_to_pubkey.
_DID_KEY_RE = re.compile(r"^did:key:z[1-9A-HJ-NP-Za-km-z]{46,48}$")
_ATTEST_RE = re.compile(r"^stamp:[0-9a-f-]{8,64}$")
_PKG_VER_RE = re.compile(r"^[a-z0-9_.-]{1,128}@[a-z0-9_.!+-]{1,64}$")


class DropError(Exception):
    """Structured ingest rejection. code is machine-parseable."""

    def __init__(self, code, message, field=None):
        super().__init__(message)
        self.code = code
        self.field = field

    def to_dict(self):
        d = {"code": self.code, "message": str(self)}
        if self.field:
            d["field"] = self.field
        return d


def _is_bool(v):
    return isinstance(v, bool)


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v):
    return _is_int(v) or isinstance(v, float)


def _parse_ts(v):
    """Strict ISO-8601 -> aware datetime, or None."""
    if not isinstance(v, str) or len(v) > 40:
        return None
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None  # naive timestamps are ambiguous -- reject
    return dt


def _canon_ts(dt):
    """Canonical timestamp form: UTC, seconds precision, 'Z' suffix.
    The ledger compares timestamps lexically (SQL ORDER BY, expiry
    filters) -- every stored timestamp must share one format or
    '…+00:00' and '…Z' misorder ('+' < 'Z' in ASCII)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _valid_url(v, require_host=True):
    if not isinstance(v, str) or len(v) > MAX_SUBJECT_VALUE:
        return False
    # Whitespace and control chars can smuggle prose/newlines into a
    # rendered field -- a URL carrying them is not a URL.
    if any(ord(c) < 33 or ord(c) == 127 for c in v):
        return False
    try:
        p = urlparse(v)
    except ValueError:
        return False
    if p.scheme not in ("http", "https"):
        return False
    if require_host and not p.hostname:
        return False
    return True


# ---------------------------------------------------------------------------
# subject.value validators -- one per subject.type. Every one produces a
# machine-parseable value; none accept prose.
# ---------------------------------------------------------------------------

def _v_http_endpoint(v):
    return _valid_url(v)


def _v_domain(v):
    return isinstance(v, str) and bool(_DOMAIN_RE.match(v))


def _v_package(v):
    return isinstance(v, str) and bool(_IDENT_RE.match(v)) and "@" not in v


def _v_package_version(v):
    return isinstance(v, str) and bool(_PKG_VER_RE.match(v))


def _v_ident(v):
    return isinstance(v, str) and bool(_IDENT_RE.match(v))


def _v_hash(v):
    return isinstance(v, str) and bool(_HASH_RE.match(v))


def _v_dropref(v):
    return isinstance(v, str) and bool(_DROPREF_RE.match(v))


def _v_api_schema(v):
    return _v_hash(v) or _valid_url(v)


_SUBJECT_VALIDATORS = {
    "http_endpoint": _v_http_endpoint,
    "domain": _v_domain,
    "package": _v_package,
    "package_version": _v_package_version,
    "mcp_server": _v_ident,
    "mcp_tool": _v_ident,
    "model_id": _v_ident,
    "task_hash": _v_hash,
    "file_hash": _v_hash,
    "api_schema": _v_api_schema,
    "drop_ref": _v_dropref,
}


# ---------------------------------------------------------------------------
# Param value validation against the vocab spec mini-language.
# ---------------------------------------------------------------------------

def _check_param(spec, value):
    tag = spec[0]
    if tag == "int":
        return _is_int(value) and spec[1] <= value <= spec[2]
    if tag == "num":
        return _is_num(value) and spec[1] <= value <= spec[2]
    if tag == "bool":
        return _is_bool(value)
    if tag == "enum":
        return isinstance(value, str) and value in spec[1]
    if tag == "ts":
        return _parse_ts(value) is not None
    if tag == "ident":
        return isinstance(value, str) and bool(_IDENT_RE.match(value))
    if tag == "hash":
        return isinstance(value, str) and bool(_HASH_RE.match(value))
    if tag == "url":
        return _valid_url(value)
    if tag == "dropref":
        return isinstance(value, str) and bool(_DROPREF_RE.match(value))
    return False


_DROP_FIELDS = {
    "v", "coord", "kind", "subject", "claim", "confidence",
    "observed_at", "expires_at", "author", "attestation", "stake",
    "refs", "pow", "sig",
}


def validate_drop(drop, now=None):
    """Validate a submitted drop object. Returns a normalized copy on
    success (params/refs defaulted, http_endpoint subjects normalized);
    the caller's object is never mutated. Raises DropError on the first
    violation.

    `pow` and `sig` are checked for shape here (presence, type); their
    cryptographic verification happens in identity.py at ingest.
    `attestation` must be null or absent on submission -- the server
    assigns it after ingest.
    """
    drop = _validate_structure(drop)

    # Temporal bounds -- ingest-only. A stored drop legitimately
    # outlives these windows, so validate_stored skips them.
    now = now or datetime.now(timezone.utc)
    observed = _parse_ts(drop["observed_at"])
    if observed > now + timedelta(minutes=5):
        raise DropError("future_observation",
                        "observed_at cannot be in the future",
                        field="observed_at")
    if observed < now - timedelta(days=MAX_OBSERVED_AGE_DAYS):
        raise DropError(
            "stale_observation",
            f"observed_at older than {MAX_OBSERVED_AGE_DAYS} days",
            field="observed_at")
    expires = _parse_ts(drop["expires_at"])
    if expires > observed + timedelta(days=MAX_TTL_DAYS):
        raise DropError(
            "bad_expiry",
            f"expires_at more than {MAX_TTL_DAYS} days past observed_at",
            field="expires_at")
    return drop


def _validate_structure(drop, stored=False):
    """Structural validation shared by ingest and read-back. When
    `stored` is True, attestation may carry a server-issued stamp id
    (it was assigned after ingest)."""
    if not isinstance(drop, dict):
        raise DropError("not_object", "drop must be a JSON object")
    # Work on a copy: normalization below must not mutate the caller's
    # object.
    drop = dict(drop)
    if isinstance(drop.get("subject"), dict):
        drop["subject"] = dict(drop["subject"])
    if isinstance(drop.get("claim"), dict):
        drop["claim"] = dict(drop["claim"])

    unknown = set(drop) - _DROP_FIELDS
    if unknown:
        raise DropError(
            "unknown_field",
            f"unknown fields: {sorted(unknown)} -- the schema is closed",
            field=sorted(unknown)[0])

    # v -- schema version. Strict int: 1.0 and True both == 1 in
    # Python, so a loose != check would let non-integer versions pass.
    # Any version in [1, SCHEMA_VERSION] is accepted: a schema bump
    # adds vocabulary, it does not invalidate drops declared under an
    # earlier version.
    if not _is_int(drop.get("v")) or not 1 <= drop["v"] <= SCHEMA_VERSION:
        raise DropError("bad_version",
                        f"v must be an integer in [1, {SCHEMA_VERSION}]",
                        field="v")

    # coord
    coord = drop.get("coord")
    if not isinstance(coord, str) or not _COORD_RE.match(coord):
        raise DropError("bad_coord",
                        "coord must be 'sha256:' + 64 lowercase hex",
                        field="coord")

    # kind
    kind = drop.get("kind")
    if kind not in vocab.KINDS:
        raise DropError("bad_kind",
                        f"kind must be one of {list(vocab.KINDS)}",
                        field="kind")

    # subject
    subject = drop.get("subject")
    if not isinstance(subject, dict):
        raise DropError("bad_subject", "subject must be an object",
                        field="subject")
    if set(subject) - {"type", "value"} or "type" not in subject \
            or "value" not in subject:
        raise DropError("bad_subject",
                        "subject must have exactly 'type' and 'value'",
                        field="subject")
    stype = subject["type"]
    if stype not in vocab.SUBJECT_TYPES:
        raise DropError(
            "bad_subject_type",
            f"subject.type must be one of {list(vocab.SUBJECT_TYPES)}",
            field="subject.type")
    sval = subject["value"]
    if not isinstance(sval, str) or len(sval) > MAX_SUBJECT_VALUE:
        raise DropError("bad_subject_value",
                        "subject.value must be a bounded string",
                        field="subject.value")
    if stype == "domain":
        sval = sval.lower()  # normalize before validating
    if not _SUBJECT_VALIDATORS[stype](sval):
        raise DropError(
            "bad_subject_value",
            f"subject.value does not validate as {stype}",
            field="subject.value")
    if stype == "http_endpoint":
        # Normalize so the same endpoint carries the same subject
        # string everywhere -- consistent with coordinate derivation.
        from deadcowboy_mcp import coords
        try:
            drop["subject"]["value"] = coords.normalize_uri(sval)
        except coords.CoordError:
            raise DropError("bad_subject_value",
                            "subject.value does not normalize",
                            field="subject.value")
    elif stype == "domain":
        drop["subject"]["value"] = sval

    # claim
    claim = drop.get("claim")
    if not isinstance(claim, dict):
        raise DropError("bad_claim", "claim must be an object",
                        field="claim")
    if set(claim) - {"predicate", "params"} or "predicate" not in claim:
        raise DropError("bad_claim",
                        "claim must have 'predicate' and optional 'params'",
                        field="claim")
    predicate = claim["predicate"]
    spec = vocab.params_spec(kind, predicate)
    if spec is None:
        raise DropError(
            "bad_predicate",
            f"'{predicate}' is not a valid predicate for kind '{kind}'",
            field="claim.predicate")

    params = claim.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise DropError("bad_params", "claim.params must be an object",
                        field="claim.params")
    if len(params) > MAX_PARAM_KEYS:
        raise DropError("bad_params",
                        f"claim.params exceeds {MAX_PARAM_KEYS} keys",
                        field="claim.params")
    required = vocab.required_params(kind, predicate)
    optional = vocab.optional_params(kind, predicate)
    missing = required - set(params)
    if missing:
        raise DropError("missing_param",
                        f"missing required params: {sorted(missing)}",
                        field=f"claim.params.{sorted(missing)[0]}")
    extra = set(params) - required - optional
    if extra:
        raise DropError(
            "unknown_param",
            f"params not in the '{predicate}' schema: {sorted(extra)}",
            field=f"claim.params.{sorted(extra)[0]}")
    for key, value in params.items():
        if not _check_param(spec[key], value):
            raise DropError(
                "bad_param",
                f"param '{key}' fails the '{predicate}' schema",
                field=f"claim.params.{key}")
    claim["params"] = params  # normalized: absent -> {}

    # confidence
    conf = drop.get("confidence")
    if not _is_num(conf) or not 0.0 <= conf <= 1.0:
        raise DropError("bad_confidence",
                        "confidence must be a number in [0.0, 1.0]",
                        field="confidence")

    # observed_at / expires_at -- parse and canonicalize here; the
    # temporal window checks live in validate_drop (ingest only).
    observed = _parse_ts(drop.get("observed_at"))
    if observed is None:
        raise DropError("bad_observed_at",
                        "observed_at must be ISO-8601 with timezone",
                        field="observed_at")
    expires = _parse_ts(drop.get("expires_at"))
    if expires is None:
        raise DropError("bad_expires_at",
                        "expires_at must be ISO-8601 with timezone",
                        field="expires_at")
    if expires <= observed:
        raise DropError("bad_expiry",
                        "expires_at must be after observed_at",
                        field="expires_at")
    # Canonical form: the ledger compares timestamps lexically.
    drop["observed_at"] = _canon_ts(observed)
    drop["expires_at"] = _canon_ts(expires)

    # author -- did:key
    author = drop.get("author")
    if not isinstance(author, str) or not _DID_KEY_RE.match(author):
        raise DropError("bad_author",
                        "author must be a did:key DID",
                        field="author")

    # attestation -- server-assigned; MUST be null or absent on
    # submit. Accepting a caller-supplied 'stamp:<id>' would let a drop
    # be stored carrying an attestation the server never issued. On
    # read-back a stored drop legitimately carries one.
    att = drop.get("attestation")
    if att is not None and not (
            stored and isinstance(att, str) and _ATTEST_RE.match(att)):
        raise DropError("bad_attestation",
                        "attestation is server-assigned; submit null",
                        field="attestation")

    # stake -- phase 3, must be null
    if drop.get("stake") is not None:
        raise DropError("stake_unsupported",
                        "stake is reserved for phase 3; must be null",
                        field="stake")

    # refs
    refs = drop.get("refs", [])
    if refs is None:
        refs = []
    if not isinstance(refs, list) or len(refs) > MAX_REFS:
        raise DropError("bad_refs",
                        f"refs must be a list of at most {MAX_REFS} "
                        "drop ids", field="refs")
    for r in refs:
        if not isinstance(r, str) or not _DROPREF_RE.match(r):
            raise DropError("bad_ref",
                            "each ref must be 'drop:' + 64 hex",
                            field="refs")
    drop["refs"] = list(refs)

    # contradiction drops must reference their target
    if kind == "contradiction":
        target = params.get("target")
        if not target:
            raise DropError("missing_param",
                            "contradiction requires params.target",
                            field="claim.params.target")
        if target not in refs:
            raise DropError(
                "ref_mismatch",
                "contradiction target must appear in refs",
                field="refs")

    # pow -- shape only; verified at ingest
    pow_obj = drop.get("pow")
    if not isinstance(pow_obj, dict) \
            or not _is_int(pow_obj.get("nonce")) \
            or pow_obj.get("nonce", -1) < 0 \
            or not _is_int(pow_obj.get("difficulty")) \
            or not 0 <= pow_obj.get("difficulty", -1) <= 64:
        raise DropError(
            "bad_pow",
            "pow must be {nonce: int>=0, difficulty: int 0..64}",
            field="pow")

    # sig -- base64url ed25519 signature (shape only; verified at ingest)
    sig = drop.get("sig")
    if not isinstance(sig, str) or not re.match(
            r"^[A-Za-z0-9_-]{80,96}$", sig):
        raise DropError("bad_sig",
                        "sig must be a base64url ed25519 signature",
                        field="sig")

    return drop


def validate_stored(body):
    """Re-validate a drop read back from the ledger. Stored data is
    untrusted input: a field validated as an enum at write time is not
    trusted as safe at read time. Returns the normalized drop, or None
    if the stored body fails structural validation.

    Temporal bounds (observed age, TTL) are skipped -- an expired drop
    is still a valid record, just an invisible one."""
    try:
        return _validate_structure(dict(body), stored=True)
    except DropError:
        return None


def signed_content(drop):
    """The canonical signed payload: the drop minus server-assigned and
    self-referential fields (attestation, sig, pow) and the reserved
    stake field -- stake is always null today and must not be
    load-bearing in the signature until phase 3 gives it meaning."""
    return {k: v for k, v in drop.items()
            if k not in ("attestation", "sig", "pow", "stake")}
