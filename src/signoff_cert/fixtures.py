"""signoff_cert.fixtures — the conformance corpus generator.

THIS IS WHAT MAKES IT A STANDARD. A spec plus one implementation is a library; a spec plus a
corpus of certificates that every conforming verifier MUST accept and MUST reject is a standard.
Each invalid fixture below isolates exactly one defect, so a verifier that fails the suite gets
told which rule it broke rather than that "something" is wrong.

The invalid cases are deliberately the ones that a naive verifier passes:

  * `tighter_bound_than_evidence` -- digests all match, signature fine, and the producer simply
    claimed more confidence than its own k/n supports. Only a verifier that RECOMPUTES catches it.
  * `conformal_below_floor` -- a miscoverage that is arithmetically unreachable at that n.
  * `partial_enumeration_zero` -- a 0.0 "exhaustive" bound over a partial enumeration.
  * `copied_ctlog_leaf` -- a valid transparency leaf lifted from a different certificate.
  * `missing_bound_type` -- a bare number whose meaning is undefined.
  * `rounded_bound_tighter` -- a bound printed to four decimal places, which rounds it DOWN.

Every fixture is sealed with HMAC so the corpus stays verifiable with no crypto dependency. The
Ed25519 authority path -- and specifically that a self-signed certificate grades `self-consistent`
and never `authenticated` -- is asserted in the test suite instead, where the optional dependency
can be skipped cleanly rather than making the corpus unrunnable.

Regenerate the on-disk corpus with `signoff-cert fixtures --out fixtures/`.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict

from .canonical import content_sha256, semantic_sha256

_HMAC_KEY = b"conformance-corpus-key-not-a-secret"


def _seal(cert: Dict[str, Any], *, sign: bool = False) -> Dict[str, Any]:
    """Attach the digests (and optionally an HMAC signature) the way a producer must."""
    cert.pop("digests", None)
    cert.pop("signature", None)
    rec = content_sha256(cert)
    cert["digests"] = {"semantic_sha256": semantic_sha256(cert), "record_sha256": rec}
    if sign:
        cert["signature"] = {
            "alg": "HMAC-SHA256", "key_id": "conformance",
            "sig": hmac.new(_HMAC_KEY, rec.encode(), hashlib.sha256).hexdigest()}
    return cert


def _base(**over: Any) -> Dict[str, Any]:
    cert: Dict[str, Any] = {
        "schema": "signoff-cert/v1",
        "domain": "kv-isolation",
        "subject": {"id": "demo-subject",
                    "artifact_digests": {"config": "a" * 64}},
        "claim": {"property": "no cross-tenant cache reuse on a byte-identical prefix"},
        "verdict": "ADMITTED",
        "gate": {"name": "demo-gate", "provenance": "conformance corpus",
                 "legs": {"partition_bound": True, "salt_present": True}},
        "confidence": {
            "method": "clopper-pearson",
            # Full precision, NOT rounded. Rounding a false-pass bound DOWN claims confidence the
            # evidence does not support -- see the `rounded_bound_tighter` invalid fixture.
            "false_pass_bound": 0.02951304959181542,
            "bound_type": "false_pass_rate_upper",
            "coverage_level": 0.95,
            "n_samples": 100,
            "machine_checked": False,
            "paper": "Clopper-Pearson 1934",
            "scope": "one engine build, one GPU class; static co-batching only",
        },
        "evidence": {"k": 0, "n": 100},
        "honesty": {"proven": [], "simulated": [], "aspirational": [], "non_claims": [
            "does not measure throughput", "no claim about any commercial provider"]},
    }
    for k, v in over.items():
        cert[k] = v
    return cert


def valid_cases() -> Dict[str, Dict[str, Any]]:
    """Certificates a conforming verifier MUST accept (given the stated verifier options)."""
    out: Dict[str, Dict[str, Any]] = {}

    out["minimal_admitted"] = _seal(_base(), sign=True)

    refused = _base(verdict="REFUSED")
    refused["gate"]["legs"] = {"partition_bound": False, "salt_present": True}
    out["fail_closed_refusal"] = _seal(refused, sign=True)

    # A bound that is NOT a rate. A verifier must carry the meaning, not just the number.
    mean = _base()
    mean["confidence"].update({"method": "empirical-bernstein", "false_pass_bound": 0.87,
                               "bound_type": "mean_lower", "n_samples": 500,
                               "paper": "Maurer-Pontil 2009"})
    mean["evidence"] = {"n": 500}
    out["mean_lower_not_a_rate"] = _seal(mean, sign=True)

    # The honest negative: the property CANNOT be certified at this n. bound is 1.0 and that is
    # correct, not catastrophic -- a verifier that reads it as a rate reports the opposite.
    imp = _base(verdict="REFUSED")
    imp["confidence"].update({"method": "impossibility-floor", "false_pass_bound": 1.0,
                              "bound_type": "uncertifiable_at_n", "n_samples": 12,
                              "paper": "capacity/query lower bound"})
    imp["evidence"] = {"n": 12}
    imp["gate"]["legs"] = {"sample_size_sufficient": False}
    out["uncertifiable_at_n"] = _seal(imp, sign=True)

    ex = _base()
    ex["confidence"].update({"method": "exhaustive-model-count", "false_pass_bound": 0.0,
                             "bound_type": "false_pass_rate_upper",
                             "paper": "exact enumeration"})
    ex["evidence"] = {"enumerated": 20736, "state_space": 20736}
    out["exhaustive_full_enumeration"] = _seal(ex, sign=True)

    return out


def invalid_cases() -> Dict[str, Dict[str, Any]]:
    """Certificates a conforming verifier MUST refuse, each isolating one defect."""
    out: Dict[str, Dict[str, Any]] = {}

    # Digests fine, signature fine -- the CLAIM is what is wrong. 0/100 supports ~0.0295, not 0.001.
    tight = _base()
    tight["confidence"]["false_pass_bound"] = 0.001
    out["tighter_bound_than_evidence"] = _seal(tight, sign=True)

    conf = _base()
    conf["confidence"].update({"method": "split-conformal-band", "false_pass_bound": 0.001,
                               "bound_type": "miscoverage_upper", "n_samples": 100})
    conf["evidence"] = {"n": 100}          # floor is 1/101 = 0.0099; 0.001 is unreachable
    out["conformal_below_floor"] = _seal(conf, sign=True)

    part = _base()
    part["confidence"].update({"method": "exhaustive-model-count", "false_pass_bound": 0.0,
                               "bound_type": "false_pass_rate_upper"})
    part["evidence"] = {"enumerated": 5000, "state_space": 20736}
    out["partial_enumeration_zero"] = _seal(part, sign=True)

    nob = _base()
    nob["confidence"].pop("bound_type")
    out["missing_bound_type"] = _seal(nob, sign=True)

    admit = _base()
    admit["gate"]["legs"] = {"partition_bound": False, "salt_present": True}
    out["admitted_with_failed_leg"] = _seal(admit, sign=True)

    tam = _seal(_base(), sign=True)
    tam["claim"]["property"] = "something else entirely"      # after sealing
    out["tampered_after_seal"] = tam

    copied = _seal(_base(), sign=True)
    copied["provenance"] = {"ctlog_leaf": {"log_id": "demo", "index": 7,
                                           "leaf_hash": "b" * 64, "inclusion_proof": []}}
    out["copied_ctlog_leaf"] = _seal(copied, sign=True)

    # The %.4f trap: a producer prints its bound to four places and the displayed value is
    # TIGHTER than the true one. Everything else about this certificate is impeccable. This is
    # the single most likely way a real producer emits an unsupportable bound, which is why it
    # is in the corpus rather than merely in the prose.
    rounded = _base()
    rounded["confidence"]["false_pass_bound"] = 0.0295
    out["rounded_bound_tighter"] = _seal(rounded, sign=True)

    unk = _base(domain="not-a-domain")
    out["unknown_domain"] = _seal(unk, sign=True)

    unkv = _base(verdict="MAYBE")
    out["unknown_verdict"] = _seal(unkv, sign=True)

    deep: Any = {"x": 1}
    for _ in range(80):
        deep = {"nested": deep}
    dos = _base()
    dos["subject"]["artifact_digests"] = {"deep": deep}
    out["over_nested"] = _seal(dos, sign=True)

    return out


def hmac_key() -> bytes:
    """The corpus key. Published on purpose -- these fixtures assert verifier behaviour, and a
    secret would make the suite unrunnable by the third parties it exists for."""
    return _HMAC_KEY


__all__ = ["valid_cases", "invalid_cases", "hmac_key"]
