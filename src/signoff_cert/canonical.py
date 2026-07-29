"""signoff_cert.canonical — the frozen serialization, and the two digests.

This is the entire trusted computing base of a conforming verifier. It is deliberately tiny and
deliberately boring: every hash in the format is SHA-256 over one canonical JSON encoding, fixed
here once. Changing any keyword argument below silently invalidates every certificate ever
sealed, so they are not configurable and must not become configurable.

Specification: `spec/signoff-cert-v1.md` §1 and §3.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

# Fields that are DERIVED FROM or ADDED AFTER the seal, and therefore cannot be inside the hash
# they are derived from. Excluding them is what makes content_sha256 a fixed point: seal, then
# recompute, and you get the same value back.
_POST_SEAL_TOP = ("signature", "attestation", "digests")
_POST_SEAL_PROV = ("content_sha256", "ctlog_leaf")


def canonical_bytes(obj: Any) -> bytes:
    """The frozen canonical serialization (§1). Do NOT change these kwargs.

    `default=str` makes datetimes and Decimals seal deterministically instead of raising, which
    matters because a producer that cannot seal an object tends to drop the field instead.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode()


def sha256_hex(obj: Any) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def semantic_sha256(cert: Mapping[str, Any]) -> str:
    """The MEANING of the claim (§3).

    Two certificates asserting the same property about the same domain share this digest no
    matter which gate produced them, when, or who signed it. That is what makes independent
    re-issues comparable rather than merely similar.
    """
    return sha256_hex({"schema": cert.get("schema"),
                       "domain": cert.get("domain"),
                       "claim": cert.get("claim")})


def content_sha256(cert: Mapping[str, Any]) -> str:
    """Root hash of the certificate BODY (§3), excluding every post-seal field."""
    body = {k: v for k, v in cert.items() if k not in _POST_SEAL_TOP}
    prov = body.get("provenance")
    if isinstance(prov, dict):
        body = dict(body)
        body["provenance"] = {k: v for k, v in prov.items() if k not in _POST_SEAL_PROV}
    return sha256_hex(body)


def depth(obj: Any, _level: int = 0) -> int:
    """Maximum nesting depth. A verifier must reject an over-nested certificate BEFORE hashing
    it (§8.0) -- otherwise a hostile producer can make verification itself the denial of service."""
    if _level > 200:                      # stop descending; the caller will refuse anyway
        return _level
    if isinstance(obj, dict):
        return max([_level] + [depth(v, _level + 1) for v in obj.values()])
    if isinstance(obj, (list, tuple)):
        return max([_level] + [depth(v, _level + 1) for v in obj])
    return _level


__all__ = ["canonical_bytes", "sha256_hex", "semantic_sha256", "content_sha256", "depth"]
