"""deadcowboy_mcp.coords -- coordinate derivation.

Two derivations, both producing a 32-byte hash rendered as
'sha256:<64 hex>':

    literal     -- sha256(normalize(uri)). Two agents deriving the
                   coordinate of the same endpoint get the same hash
                   only if normalization is identical, so the rules are
                   strict and documented: lowercase scheme and host,
                   strip default ports, strip fragments, sort query
                   params, strip trailing slash.

    conceptual  -- sha256(JCS(canonical_task_descriptor)). The
                   descriptor is itself a structured object with fixed
                   fields -- never a free-text task description.

Coordinates are one-way. The network stores the hash and never the
preimage, so a coordinate cannot be enumerated back into the URL it
describes.
"""

import hashlib
import re
from urllib.parse import (parse_qsl, quote, unquote, urlencode,
                          urlsplit, urlunsplit)

try:
    from stamp_mcp.server import _canonical as _jcs
except ImportError:  # pragma: no cover
    import json

    def _jcs(obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))

_COORD_PREFIX = "sha256:"
_COORD_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

# Task descriptor fields -- the conceptual coordinate's fixed shape.
# Values are bounded identifiers/enums, never prose.
_TASK_FIELDS = {"domain", "action", "subject_type", "subject_value"}
_TASK_FIELD_RE = re.compile(r"^[a-z0-9_.:/@-]{1,256}$")


class CoordError(Exception):
    pass


def _sha256_hex(text):
    return _COORD_PREFIX + hashlib.sha256(text.encode("utf-8")).hexdigest()


_UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" \
              "0123456789-._~"


def _norm_path(path):
    """Canonical path: backslashes -> slashes (WHATWG parity), RFC
    3986 dot-segment removal, percent-encoding normalized (uppercase
    hex, unreserved chars decoded). Two spellings of the same path
    must derive the same coordinate."""
    path = path.replace("\\", "/")
    # Dot-segment removal (RFC 3986 5.2.4, absolute paths).
    out = []
    for seg in path.split("/"):
        if seg == ".":
            continue
        if seg == "..":
            if out and out[-1] != "":
                out.pop()
            continue
        out.append(seg)
    path = "/".join(out)
    if not path.startswith("/"):
        path = "/" + path
    # Percent-encoding: decode unreserved, uppercase the rest.
    path = unquote(path, errors="strict")
    return quote(path, safe="/" + _UNRESERVED + "!$&'()*+,;=:@")


def _norm_host(host):
    """Canonical host: lowercase, trailing root dot stripped, IDNA
    punycode for non-ASCII, brackets restored on IPv6 literals."""
    host = host.rstrip(".")
    if not host:
        raise CoordError("uri must have a host")
    if ":" in host:  # IPv6 literal -- urlsplit strips the brackets
        return f"[{host}]"
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        raise CoordError("host is not a valid DNS name")
    return host


def normalize_uri(uri):
    """Strict URI normalization for literal coordinates.

    Rules (order matters):
      1. whitespace/control chars rejected outright
      2. scheme and host lowercased; scheme must be http/https
      3. host: trailing root dot stripped, IDNA-encoded, IPv6
         re-bracketed
      4. default port stripped; non-default port kept
      5. fragment stripped
      6. query params sorted by (key, value); blank values kept
      7. path: backslashes -> slashes, dot-segments removed,
         percent-encoding normalized, empty -> '/', trailing '/'
         stripped (except root)
      8. userinfo rejected -- credentials never enter a coordinate
    """
    if not isinstance(uri, str) or not uri or len(uri) > 2048:
        raise CoordError("uri must be a non-empty string <= 2048 chars")
    uri = uri.strip()
    # A URI carrying whitespace or control chars is not a URI -- and
    # could smuggle prose into a rendered field downstream.
    if any(ord(c) < 33 or ord(c) == 127 for c in uri):
        raise CoordError("uri contains whitespace or control chars")
    try:
        parts = urlsplit(uri)
    except ValueError as e:
        raise CoordError(f"unparseable uri: {e}")
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        # ws/wss are excluded: no subject type can express them, so a
        # derived coordinate could never carry a matching claim.
        raise CoordError(f"unsupported scheme: {scheme}")
    if parts.username or parts.password:
        raise CoordError("userinfo is not allowed in a coordinate uri")
    host = _norm_host((parts.hostname or "").lower())
    try:
        port = parts.port
    except ValueError:
        raise CoordError("invalid port")
    netloc = host
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc = f"{host}:{port}"
    path = _norm_path(parts.path or "/")
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    # Sort query params deterministically; parse_qsl preserves
    # duplicates, sorted() makes order canonical.
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((scheme, netloc, path, query, ""))


def derive_literal(uri):
    """sha256(normalize(uri)) -- the public dead drop for a resource."""
    return _sha256_hex("literal:" + normalize_uri(uri))


def derive_conceptual(descriptor):
    """sha256(JCS(task_descriptor)) -- coordinate of a structured task.

    The descriptor is a fixed-shape object: {domain, action,
    subject_type, subject_value} -- all bounded identifier strings.
    Two agents with the same structured work definition derive the same
    coordinate; a free-text description would never converge.
    """
    if not isinstance(descriptor, dict):
        raise CoordError("task descriptor must be an object")
    unknown = set(descriptor) - _TASK_FIELDS
    if unknown:
        raise CoordError(
            f"unknown descriptor fields: {sorted(unknown)} -- "
            f"allowed: {sorted(_TASK_FIELDS)}")
    missing = _TASK_FIELDS - set(descriptor)
    if missing:
        raise CoordError(f"missing descriptor fields: {sorted(missing)}")
    for key, value in descriptor.items():
        if not isinstance(value, str) or not _TASK_FIELD_RE.match(value):
            raise CoordError(
                f"descriptor.{key} must match "
                "[a-z0-9_.:/@-]{1,256} -- structured, not prose")
    # subject_type is a closed vocabulary field -- 'http_endpoint' and
    # 'endpoint' must not derive different coordinates for the same task.
    from deadcowboy_mcp import vocab
    if descriptor["subject_type"] not in vocab.SUBJECT_TYPES:
        raise CoordError(
            f"descriptor.subject_type must be one of "
            f"{list(vocab.SUBJECT_TYPES)}")
    return _sha256_hex("conceptual:" + _jcs(descriptor))


def valid_coord(coord):
    return isinstance(coord, str) and bool(_COORD_RE.match(coord))
