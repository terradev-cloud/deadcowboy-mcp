"""deadcowboy_mcp.tlog -- the transparency log.

Drops are immutable by convention; the log makes that convention
verifiable. Every accepted drop is appended as a leaf in an append-only
Merkle tree (RFC 6962 / Certificate Transparency construction). Each
append produces a signed tree head (STH): {tree_size, root_hash,
signed_at} signed by the log's own ed25519 identity.

Three proofs fall out of the construction:

- Inclusion: a compact audit path proves a given drop is in the tree
  at a given size -- a drop that was never logged cannot produce one.
- Consistency: a proof between two tree heads shows the log only grew
  -- the operator cannot fork or rewrite history without detection.
- Anchoring: STHs are periodically published to an external anchor
  (anchor.py), so even the operator cannot retroactively rewrite.

The log covers history, not visibility: expired drops stay in the tree
(the leaf proves the drop WAS in the ledger), while sweeps still only
render live drops.
"""

import hashlib
import os
import time

from deadcowboy_mcp import identity

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


# ---------------------------------------------------------------------------
# Merkle tree hash -- RFC 6962 section 2.1
# ---------------------------------------------------------------------------

def leaf_hash(data: bytes) -> bytes:
    """Hash of one leaf: SHA-256(0x00 || data). Leaf data is the drop
    id string ("drop:<64 hex>") -- self-describing, already the sha256
    of the signed content."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash of an interior node: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _largest_pow2_lt(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k < n:
        k <<= 1
    return k >> 1


def mth(hashes) -> bytes:
    """Merkle Tree Hash over a list of leaf hashes (bytes)."""
    n = len(hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashes[0]
    k = _largest_pow2_lt(n)
    return node_hash(mth(hashes[:k]), mth(hashes[k:]))


# ---------------------------------------------------------------------------
# inclusion proofs -- RFC 6962 section 2.1.1
# ---------------------------------------------------------------------------

def inclusion_path(hashes, index: int):
    """Audit path proving hashes[index] is committed in MTH(hashes)."""
    n = len(hashes)
    if n == 1:
        return []
    k = _largest_pow2_lt(n)
    if index < k:
        return inclusion_path(hashes[:k], index) + [mth(hashes[k:])]
    return inclusion_path(hashes[k:], index - k) + [mth(hashes[:k])]


def verify_inclusion(leaf: bytes, index: int, size: int, path,
                     root: bytes) -> bool:
    """Verify an audit path: leaf hash, 0-based index, tree size, path
    of sibling hashes, expected root. RFC 6962 verification algorithm."""
    if index >= size or size < 1:
        return False
    fn, sn = index, size - 1
    r = leaf
    for p in path:
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return r == root


# ---------------------------------------------------------------------------
# consistency proofs -- RFC 6962 section 2.1.2
# ---------------------------------------------------------------------------

def consistency_proof(hashes, m: int):
    """Proof that the first m leaves are a prefix of the full tree.
    `hashes` is the leaf-hash list of the LATER (larger) tree."""
    n = len(hashes)
    if m == n:
        return []
    return _subproof(hashes, m, True)


def _subproof(hashes, m: int, b: bool):
    n = len(hashes)
    if m == n:
        return [] if b else [mth(hashes)]
    k = _largest_pow2_lt(n)
    if m <= k:
        return _subproof(hashes[:k], m, b) + [mth(hashes[k:])]
    return _subproof(hashes[k:], m - k, False) + [mth(hashes[:k])]


def verify_consistency(first: int, first_hash: bytes, second: int,
                       second_hash: bytes, proof) -> bool:
    """Verify that the tree at `first` (root first_hash) is a prefix of
    the tree at `second` (root second_hash). RFC 6962 section 2.1.2."""
    if first < 1 or first > second:
        return False
    if first == second:
        return first_hash == second_hash and not proof
    proof = list(proof)
    if first & (first - 1) == 0:  # first is an exact power of two
        proof.insert(0, first_hash)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if not proof:
        return False
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_hash and sr == second_hash


# ---------------------------------------------------------------------------
# signed tree heads -- the log's own identity commits to each root
# ---------------------------------------------------------------------------

_LOG_SEED = None


def _log_seed() -> str:
    """The log's ed25519 seed: DEADCOWBOY_LOG_KEY env, else a persisted
    key file next to the database (generated once, mode 600). The log
    key is the only identity that can produce valid tree heads."""
    global _LOG_SEED
    if _LOG_SEED:
        return _LOG_SEED
    seed = os.environ.get("DEADCOWBOY_LOG_KEY")
    if not seed:
        from deadcowboy_mcp import store
        path = os.path.join(os.path.dirname(store.DB_PATH) or ".",
                            "log.key")
        if os.path.exists(path):
            with open(path) as f:
                seed = f.read().strip()
        else:
            _did, seed = identity.generate_keypair()
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600)
            try:
                os.write(fd, seed.encode())
            finally:
                os.close(fd)
    _LOG_SEED = seed
    return seed


def log_did() -> str:
    """did:key of the log's signing identity -- published in every STH
    so verifiers can pin it."""
    priv = identity.private_key_from_b64(_log_seed())
    return identity.pubkey_to_did(priv.public_key())


def sth_content(tree_size: int, root_hash: str, signed_at: float):
    """The exact dict the log signs -- kept separate so verifiers
    reconstruct it identically."""
    return {"tree_size": tree_size, "root_hash": root_hash,
            "signed_at": signed_at}


def sign_sth(tree_size: int, root_hash: str, signed_at=None):
    """Sign a tree head. Returns the full STH dict including the log's
    DID and signature."""
    signed_at = signed_at if signed_at is not None else time.time()
    content = sth_content(tree_size, root_hash, signed_at)
    return {**content, "signature": identity.sign(content, _log_seed()),
            "log_did": log_did()}


def verify_sth(sth) -> bool:
    """Verify an STH's signature against its claimed log DID."""
    try:
        content = sth_content(sth["tree_size"], sth["root_hash"],
                              sth["signed_at"])
        return identity.verify_signature(content, sth["signature"],
                                         sth["log_did"])
    except (KeyError, TypeError):
        return False
