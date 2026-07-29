"""signoff_cert.verify — the reference verifier for `signoff-cert/v1`.

FAIL-CLOSED IS THE WHOLE DESIGN. Every step in §8 is required; any failure, and any internal
error, collapses the effective verdict to `REFUSED`. This function does not raise. A verifier
that throws on malformed input is a verifier that a hostile producer can turn into an outage,
and -- worse -- a caller who wraps it in `try/except: pass` has silently built an admit-by-default
gate out of a fail-closed one.

TWO RESULTS, NOT ONE. `ok` is the policy decision. `trust_level` reports how far the certificate
actually got:

    unverified  <  self-consistent  <  authenticated  <  anchored

That distinction is the honest part. An Ed25519 signature checked against the pubkey embedded in
the same certificate proves the object is internally consistent and proves nothing about who made
it -- anyone can generate a keypair. It grades as `self-consistent`, never `authenticated`.
Reaching `authenticated` requires a key supplied OUT OF BAND: an HMAC key you hold, or a pinned
operator public key. Collapsing those two states is the most common way a signature check becomes
decorative, so the grading keeps them apart by construction.

Specification: `spec/signoff-cert-v1.md` §8.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from .bounds import BOUND_TYPES, METHODS, recompute
from .canonical import content_sha256, depth, semantic_sha256

VERDICTS = ("ADMITTED", "REJECTED", "REFUSED")
DOMAINS = ("litho", "em-signoff", "zk-hw", "code-rewrite", "wifi-pqc", "telecom", "kv-isolation")

MAX_DEPTH = 64                     # §8.0 DoS guard, applied BEFORE hashing
TRUST_ORDER = ("unverified", "self-consistent", "authenticated", "anchored")


@dataclass
class VerifyResult:
    ok: bool
    effective_verdict: str
    trust_level: str
    checks: dict = field(default_factory=dict)
    reasons: list = field(default_factory=list)
    recomputed_bound: Optional[float] = None
    bound_rechecked: bool = False

    def as_dict(self) -> dict:
        return {"ok": self.ok, "effective_verdict": self.effective_verdict,
                "trust_level": self.trust_level, "checks": self.checks,
                "reasons": self.reasons, "recomputed_bound": self.recomputed_bound,
                "bound_rechecked": self.bound_rechecked}


def _fail(reasons: list, checks: dict, msg: str, key: str) -> None:
    checks[key] = False
    reasons.append(msg)


def verify_certificate(
    cert: Any,
    *,
    hmac_key: Optional[bytes] = None,
    pinned_pubkey: Optional[str] = None,
    require_authentication: bool = True,
    gate_rerun: Optional[Callable[[Mapping[str, Any]], str]] = None,
) -> VerifyResult:
    """Verify a certificate against §8. Never raises.

    `require_authentication` defaults to True per §8.4: an unauthenticated certificate is
    tamper-evident but not attributable, and by default is not admissible. Set it False only if
    you genuinely mean "I am checking integrity, not origin" -- and say so where the result lands.
    """
    checks: dict = {}
    reasons: list = []
    trust = "unverified"

    try:
        # -- 0. structural validity, depth-guarded BEFORE any hashing -------------------------
        if not isinstance(cert, Mapping):
            return VerifyResult(False, "REFUSED", trust, {"structure": False},
                                ["certificate is not a JSON object"])
        d = depth(cert)
        if d > MAX_DEPTH:
            return VerifyResult(False, "REFUSED", trust, {"depth": False},
                                [f"nesting depth {d} exceeds {MAX_DEPTH}; refused before hashing"])
        checks["depth"] = True

        ok_struct = True
        if cert.get("schema") != "signoff-cert/v1":
            _fail(reasons, checks, f"unknown schema {cert.get('schema')!r}", "schema")
            ok_struct = False
        else:
            checks["schema"] = True

        if cert.get("domain") not in DOMAINS:
            _fail(reasons, checks, f"unknown domain {cert.get('domain')!r}", "domain")
            ok_struct = False
        else:
            checks["domain"] = True

        verdict = cert.get("verdict")
        if verdict not in VERDICTS:
            _fail(reasons, checks, f"unknown verdict {verdict!r}", "verdict")
            ok_struct = False
        else:
            checks["verdict"] = True

        for req in ("subject", "claim", "gate", "confidence", "digests"):
            if not isinstance(cert.get(req), Mapping):
                _fail(reasons, checks, f"missing or malformed required block {req!r}", f"has_{req}")
                ok_struct = False

        conf = cert.get("confidence") if isinstance(cert.get("confidence"), Mapping) else {}
        method, btype = conf.get("method"), conf.get("bound_type")
        bound = conf.get("false_pass_bound")

        if method not in METHODS:
            _fail(reasons, checks, f"unknown confidence method {method!r}", "method")
            ok_struct = False
        else:
            checks["method"] = True
        if btype not in BOUND_TYPES:
            _fail(reasons, checks,
                  f"missing or unknown bound_type {btype!r}; the number's MEANING is undefined",
                  "bound_type")
            ok_struct = False
        else:
            checks["bound_type"] = True
        if not isinstance(bound, (int, float)) or isinstance(bound, bool) or bound != bound \
                or bound in (float("inf"), float("-inf")):
            _fail(reasons, checks, "false_pass_bound is missing or not finite", "bound_finite")
            ok_struct = False
        else:
            checks["bound_finite"] = True

        checks["structure"] = ok_struct

        # -- 1. digests -----------------------------------------------------------------------
        digests = cert.get("digests") if isinstance(cert.get("digests"), Mapping) else {}
        sem, rec = semantic_sha256(cert), content_sha256(cert)
        if digests.get("semantic_sha256") != sem:
            _fail(reasons, checks,
                  f"semantic_sha256 mismatch (recorded {digests.get('semantic_sha256')!r}, "
                  f"recomputed {sem!r})", "semantic_digest")
        else:
            checks["semantic_digest"] = True
        if digests.get("record_sha256") != rec:
            _fail(reasons, checks,
                  f"record_sha256 mismatch (recorded {digests.get('record_sha256')!r}, "
                  f"recomputed {rec!r})", "record_digest")
        else:
            checks["record_digest"] = True
        prov = cert.get("provenance") if isinstance(cert.get("provenance"), Mapping) else {}
        if "content_sha256" in prov and prov.get("content_sha256") != rec:
            _fail(reasons, checks, "provenance.content_sha256 does not match the body",
                  "provenance_digest")

        if checks.get("semantic_digest") and checks.get("record_digest"):
            trust = "self-consistent"

        # -- 2. gate replay -------------------------------------------------------------------
        gate = cert.get("gate") if isinstance(cert.get("gate"), Mapping) else {}
        legs = gate.get("legs") if isinstance(gate.get("legs"), Mapping) else {}
        if legs:
            all_pass = all(bool(v) for v in legs.values())
            # Domain-free replay checks verdict<->legs CONSISTENCY only. The legs are
            # producer-authored, so this cannot attest they are real; §8.2 says so plainly and
            # so does the reason string, rather than letting a green tick imply more.
            expected = "ADMITTED" if all_pass else "REFUSED"
            if verdict == "ADMITTED" and not all_pass:
                failed = [k for k, v in legs.items() if not v]
                _fail(reasons, checks,
                      f"verdict ADMITTED but gate legs {failed} are false", "gate_consistency")
            else:
                checks["gate_consistency"] = True
                if verdict != expected and verdict != "REJECTED":
                    reasons.append(f"note: verdict {verdict} with legs all-pass={all_pass}")
        if gate_rerun is not None:
            try:
                reproduced = gate_rerun(cert)
                if reproduced != verdict:
                    _fail(reasons, checks,
                          f"gate re-run reproduced {reproduced!r}, recorded {verdict!r}",
                          "gate_rerun")
                else:
                    checks["gate_rerun"] = True
            except Exception as e:                       # a broken re-runner must not admit
                _fail(reasons, checks, f"gate re-run raised: {e!r}", "gate_rerun")

        # -- 3. recompute the bound, incl. the finite-sample feasibility floor -----------------
        recomputed, infeasible = recompute(cert)
        result_bound, rechecked = recomputed, recomputed is not None
        if infeasible:
            _fail(reasons, checks, infeasible, "bound_feasible")
        elif recomputed is not None and isinstance(bound, (int, float)):
            checks["bound_feasible"] = True
            if bound < recomputed - 1e-9:
                _fail(reasons, checks,
                      f"recorded bound {bound:g} is TIGHTER than the recomputed {recomputed:g}: "
                      f"the evidence does not support the claimed confidence", "bound_recheck")
            else:
                checks["bound_recheck"] = True
        else:
            reasons.append("bound not independently rechecked (raw stream not carried inline)")

        # -- 4. authentication ----------------------------------------------------------------
        sig = cert.get("signature") if isinstance(cert.get("signature"), Mapping) else None
        authenticated = False
        if sig:
            alg = sig.get("alg")
            if alg == "HMAC-SHA256":
                if hmac_key is None:
                    reasons.append("HMAC signature present but no key supplied: NOT authenticated")
                else:
                    want = hmac.new(hmac_key, rec.encode(), hashlib.sha256).hexdigest()
                    if hmac.compare_digest(want, str(sig.get("sig", ""))):
                        authenticated = True
                        checks["signature"] = True
                    else:
                        _fail(reasons, checks, "HMAC signature does not verify", "signature")
            elif alg == "Ed25519":
                if pinned_pubkey is None:
                    # Verifying against the embedded pubkey proves self-consistency only.
                    reasons.append(
                        "Ed25519 verified against its OWN embedded pubkey is self-consistent, "
                        "NOT authenticated; supply a pinned operator key")
                elif str(sig.get("pubkey", "")) != pinned_pubkey:
                    _fail(reasons, checks,
                          "embedded pubkey does not match the pinned operator key", "signature")
                else:
                    ok_sig = _ed25519_ok(rec, sig, pinned_pubkey)
                    if ok_sig is None:
                        reasons.append("Ed25519 present but no verifier available "
                                       "(install `cryptography` for the authority path)")
                    elif ok_sig:
                        authenticated = True
                        checks["signature"] = True
                    else:
                        _fail(reasons, checks, "Ed25519 signature does not verify", "signature")
            else:
                _fail(reasons, checks, f"unknown signature alg {alg!r}", "signature")
        if authenticated:
            trust = "authenticated"
        elif require_authentication:
            _fail(reasons, checks,
                  "not authenticated (§8.4 default-required): supply an HMAC key or a pinned "
                  "Ed25519 operator key, or set require_authentication=False and say so",
                  "authenticated")

        # -- 6. transparency anchoring --------------------------------------------------------
        leaf = prov.get("ctlog_leaf") if isinstance(prov.get("ctlog_leaf"), Mapping) else None
        if leaf:
            bound_to = leaf.get("leaf_hash")
            expect = hashlib.sha256(b"\x00" + rec.encode()).hexdigest()
            if bound_to != expect:
                _fail(reasons, checks,
                      "ctlog leaf_hash does not bind to THIS certificate (a leaf copied from "
                      "another certificate must fail)", "ctlog_binding")
            else:
                checks["ctlog_binding"] = True
                if authenticated:
                    trust = "anchored"

        ok = all(v for v in checks.values() if isinstance(v, bool))
        effective = verdict if ok and verdict in VERDICTS else "REFUSED"
        return VerifyResult(ok, effective, trust, checks, reasons, result_bound, rechecked)

    except Exception as e:                       # §8: any internal error collapses to REFUSED
        return VerifyResult(False, "REFUSED", trust, {"internal": False},
                            [f"verifier error, refused by default: {e!r}"])


def _ed25519_ok(content: str, sig: Mapping[str, Any], pubkey_hex: str) -> Optional[bool]:
    """True/False if a verifier is available, None if not. Optional dependency by design: the
    integrity path must stay dependency-free, and only the AUTHORITY path needs crypto."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except Exception:
        return None
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pk.verify(bytes.fromhex(str(sig.get("sig", ""))), content.encode())
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


__all__ = ["verify_certificate", "VerifyResult", "VERDICTS", "DOMAINS", "TRUST_ORDER", "MAX_DEPTH"]
