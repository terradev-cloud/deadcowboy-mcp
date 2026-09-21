"""deadcowboy_mcp.identity -- did:key authorship and proof-of-work.

Author identity is a DID keypair. Every drop is signed; the network
verifies the signature and rejects unsigned drops. An author is a stable
identity across sessions without requiring an account.

did:key encoding: 'did:key:z' + base58btc(0xed01 || ed25519_pubkey).
The 0xed01 multicodec prefix marks an ed25519 public key.

Proof-of-work: a drop carries pow = {nonce, difficulty} such that
sha256(drop_id || ':' || nonce) has `difficulty` leading zero bits.
Trivial for one drop, expensive for ten thousand -- the spam floor with
no token, no payment rail, no account.
"""

import base64
import hashlib
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption)

try:
    from stamp_mcp.server import _canonical as _jcs
except ImportError:  # pragma: no cover
    import json

    def _jcs(obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))

_ED25519_MULTICODEC = b"\xed\x01"
# ed25519 did:key = 'did:key:z' + base58btc(0xed01 || 32-byte pubkey)
# = 34 bytes -> 46-48 base58 chars. Same bound as schema._DID_KEY_RE.
_DID_KEY_RE = re.compile(r"^did:key:z[1-9A-HJ-NP-Za-km-z]{46,48}$")
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}

DEFAULT_DIFFICULTY = 18  # ~260k hashes avg; <1s on one core


class IdentityError(Exception):
    pass


# ---------------------------------------------------------------------------
# base58btc (bitcoin alphabet) -- inline to keep deps at cryptography only
# ---------------------------------------------------------------------------

def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58_ALPHABET[r] + out
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + (out or "")


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in _B58_INDEX:
            raise IdentityError("invalid base58 character")
        n = n * 58 + _B58_INDEX[c]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


# ---------------------------------------------------------------------------
# did:key
# ---------------------------------------------------------------------------

def generate_keypair():
    """-> (did, private_key_b64url). The private key is raw 32-byte seed,
    base64url -- the caller holds it; the server never stores it."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    seed = priv.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    did = "did:key:z" + b58encode(_ED25519_MULTICODEC + pub)
    return did, base64.urlsafe_b64encode(seed).decode().rstrip("=")


def did_to_pubkey(did: str) -> Ed25519PublicKey:
    if not isinstance(did, str) or not _DID_KEY_RE.match(did):
        raise IdentityError("not a did:key DID")
    raw = b58decode(did[len("did:key:z"):])
    if len(raw) != 34 or raw[:2] != _ED25519_MULTICODEC:
        raise IdentityError("did:key is not an ed25519 key")
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def pubkey_to_did(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "did:key:z" + b58encode(_ED25519_MULTICODEC + raw)


def private_key_from_b64(seed_b64: str) -> Ed25519PrivateKey:
    try:
        seed = base64.urlsafe_b64decode(seed_b64 + "=" * (-len(seed_b64) % 4))
        return Ed25519PrivateKey.from_private_bytes(seed)
    except Exception:
        raise IdentityError("invalid private key encoding")


# ---------------------------------------------------------------------------
# signatures -- ed25519 over the JCS canonical form of the signed content
# ---------------------------------------------------------------------------

def sign(content: dict, seed_b64: str) -> str:
    """Sign canonical(content); returns base64url signature."""
    priv = private_key_from_b64(seed_b64)
    sig = priv.sign(_jcs(content).encode("utf-8"))
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")


def verify_signature(content: dict, sig_b64: str, did: str) -> bool:
    # ed25519 verification is constant-time in the signature bytes --
    # the only early exits are malformed input (bad DID, bad base64),
    # which leak nothing about a well-formed forgery attempt.
    try:
        pub = did_to_pubkey(did)
        sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        pub.verify(sig, _jcs(content).encode("utf-8"))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# drop id + proof-of-work
# ---------------------------------------------------------------------------

def drop_id(content: dict) -> str:
    """drop:<sha256 of canonical signed content>."""
    return "drop:" + hashlib.sha256(
        _jcs(content).encode("utf-8")).hexdigest()


def _pow_hash(did_drop: str, nonce: int) -> bytes:
    return hashlib.sha256(f"{did_drop}:{nonce}".encode()).digest()


def _leading_zero_bits(digest: bytes) -> int:
    """Leading zero bits, counted over the WHOLE digest -- constant
    work regardless of where the first nonzero byte falls. An
    early-exit loop would make rejection timing proportional to how
    close the hash came to the target; the count itself is public
    (anyone can hash), but the check should not leak it for free."""
    bits = 0
    hit = False
    for b in digest:
        if hit:
            continue
        if b == 0:
            bits += 8
        else:
            bits += 8 - b.bit_length()
            hit = True
    return bits


def check_pow(did_drop: str, nonce: int, difficulty: int) -> bool:
    return _leading_zero_bits(_pow_hash(did_drop, nonce)) >= difficulty


def solve_pow(did_drop: str, difficulty: int = DEFAULT_DIFFICULTY,
              start: int = 0, max_iter: int = 50_000_000,
              budget_s: float = 30.0):
    """Find a nonce satisfying the difficulty target. Returns nonce or
    None if max_iter exhausted or the time budget runs out -- a high
    configured difficulty must not pin an executor thread forever."""
    import time as _t
    deadline = _t.monotonic() + budget_s
    nonce = start
    for i in range(max_iter):
        if check_pow(did_drop, nonce, difficulty):
            return nonce
        nonce += 1
        if i & 0xFFF == 0xFFF and _t.monotonic() > deadline:
            return None
    return None
