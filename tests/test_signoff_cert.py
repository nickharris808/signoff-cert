"""Test suite for signoff-cert. Every test plants a specific defect and asserts the rule fires."""
from __future__ import annotations

import json
import math
from math import comb

import pytest

from signoff_cert import (
    canonical_bytes,
    clopper_pearson_upper,
    content_sha256,
    describe_bound,
    invalid_cases,
    semantic_sha256,
    valid_cases,
    verify_certificate,
)
from signoff_cert.bounds import betai, recompute, zero_observed_ceiling
from signoff_cert.canonical import depth
from signoff_cert.fixtures import hmac_key

KEY = hmac_key()


# ---------------------------------------------------------------- conformance corpus

def test_every_valid_fixture_is_accepted():
    for name, cert in valid_cases().items():
        r = verify_certificate(cert, hmac_key=KEY)
        assert r.ok, f"valid/{name} was refused: {r.reasons}"


def test_every_invalid_fixture_is_refused():
    """The load-bearing direction. A verifier that accepts these is worse than no verifier."""
    for name, cert in invalid_cases().items():
        r = verify_certificate(cert, hmac_key=KEY)
        assert not r.ok, f"invalid/{name} was ACCEPTED"
        assert r.effective_verdict == "REFUSED"


@pytest.mark.parametrize("name", sorted(invalid_cases()))
def test_each_invalid_fixture_names_its_own_defect(name):
    """A refusal must say which rule broke, or the corpus cannot be used to fix a verifier."""
    r = verify_certificate(invalid_cases()[name], hmac_key=KEY)
    assert r.reasons, f"invalid/{name} refused with no reason given"


# ---------------------------------------------------------------- canonicalization

def test_canonical_form_is_key_order_independent():
    a = {"b": 1, "a": {"y": 2, "x": 3}}
    b = {"a": {"x": 3, "y": 2}, "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b)


def test_canonical_form_has_no_incidental_whitespace():
    assert b" " not in canonical_bytes({"a": 1, "b": [1, 2]})


def test_content_digest_is_a_fixed_point():
    """Sealing then recomputing must yield the same value, or no certificate is stable."""
    cert = dict(valid_cases()["minimal_admitted"])
    assert content_sha256(cert) == cert["digests"]["record_sha256"]


def test_semantic_digest_ignores_gate_internals():
    """Two certificates asserting the same thing must share a semantic digest."""
    a = dict(valid_cases()["minimal_admitted"])
    b = json.loads(json.dumps(a))
    b["gate"] = {"name": "a totally different gate", "provenance": "elsewhere", "legs": {"x": True}}
    assert semantic_sha256(a) == semantic_sha256(b)


def test_semantic_digest_changes_when_the_claim_changes():
    a = dict(valid_cases()["minimal_admitted"])
    b = json.loads(json.dumps(a))
    b["claim"]["property"] = "a different property"
    assert semantic_sha256(a) != semantic_sha256(b)


# ---------------------------------------------------------------- the bound

def test_clopper_pearson_matches_the_closed_form_at_k_zero():
    """For k=0 the exact limit is 1 - alpha**(1/n); no approximation is acceptable here."""
    for n in (10, 100, 250, 1000):
        assert clopper_pearson_upper(0, n, 0.95) == pytest.approx(1 - 0.05 ** (1.0 / n), abs=1e-12)


@pytest.mark.parametrize("k,n", [(0, 100), (1, 100), (5, 100), (3, 250)])
def test_clopper_pearson_inverts_the_binomial_cdf(k, n):
    """The defining property: P[X <= k | p*] must equal alpha exactly."""
    p = clopper_pearson_upper(k, n, 0.95)
    cdf = sum(comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k + 1))
    assert cdf == pytest.approx(0.05, abs=1e-9)


def test_bound_is_conservative_not_optimistic():
    """More trials must never LOOSEN the bound."""
    prev = 1.0
    for n in (10, 50, 100, 500, 1000):
        cur = zero_observed_ceiling(n)
        assert cur < prev
        prev = cur


def test_betai_endpoints():
    assert betai(2, 3, 0.0) == 0.0
    assert betai(2, 3, 1.0) == 1.0


def test_a_bound_tighter_than_its_evidence_is_refused():
    cert = json.loads(json.dumps(valid_cases()["minimal_admitted"]))
    cert["confidence"]["false_pass_bound"] = 0.001            # 0/100 does not support this
    from signoff_cert.fixtures import _seal
    r = verify_certificate(_seal(cert, sign=True), hmac_key=KEY)
    assert not r.ok
    assert any("TIGHTER" in x for x in r.reasons)


def test_a_looser_bound_than_evidence_is_allowed():
    """Overstating your uncertainty is always permitted; understating it never is."""
    cert = json.loads(json.dumps(valid_cases()["minimal_admitted"]))
    cert["confidence"]["false_pass_bound"] = 0.5
    from signoff_cert.fixtures import _seal
    assert verify_certificate(_seal(cert, sign=True), hmac_key=KEY).ok


def test_conformal_below_the_finite_sample_floor_is_infeasible_not_optimistic():
    cert = invalid_cases()["conformal_below_floor"]
    _, reason = recompute(cert)
    assert reason and "UNREACHABLE" in reason


def test_exhaustive_zero_over_partial_enumeration_is_refused():
    _, reason = recompute(invalid_cases()["partial_enumeration_zero"])
    assert reason and "partial enumeration" in reason.lower()


def test_bound_type_meaning_is_never_collapsed_to_a_rate():
    """A mean_lower of 0.87 is excellent; read as a failure rate it is a catastrophe."""
    assert "LOWER bound" in describe_bound({"false_pass_bound": 0.87, "bound_type": "mean_lower"})
    assert "UNCERTIFIABLE" in describe_bound(
        {"false_pass_bound": 1.0, "bound_type": "uncertifiable_at_n"})
    assert "at most" in describe_bound(
        {"false_pass_bound": 0.03, "bound_type": "false_pass_rate_upper"})


# ---------------------------------------------------------------- fail-closed behaviour

@pytest.mark.parametrize("junk", [None, 42, "a string", [], {"schema": "other/v1"}, {}])
def test_verifier_never_raises_and_refuses_by_default(junk):
    """§8: any malformed input collapses to REFUSED. A verifier that throws is an outage."""
    r = verify_certificate(junk, hmac_key=KEY)
    assert r.ok is False
    assert r.effective_verdict == "REFUSED"


def test_over_nested_certificate_is_refused_before_hashing():
    r = verify_certificate(invalid_cases()["over_nested"], hmac_key=KEY)
    assert not r.ok
    assert any("depth" in x for x in r.reasons)


def test_depth_helper_terminates_on_deep_input():
    deep = {"x": 1}
    for _ in range(500):
        deep = {"n": deep}
    assert depth(deep) > 100          # returns rather than blowing the stack


def test_a_broken_gate_rerun_refuses_rather_than_admits():
    def exploding(_cert):
        raise RuntimeError("gate unavailable")
    r = verify_certificate(valid_cases()["minimal_admitted"], hmac_key=KEY, gate_rerun=exploding)
    assert not r.ok


def test_gate_rerun_disagreement_is_refused():
    r = verify_certificate(valid_cases()["minimal_admitted"], hmac_key=KEY,
                           gate_rerun=lambda c: "REJECTED")
    assert not r.ok
    assert any("reproduced" in x for x in r.reasons)


# ---------------------------------------------------------------- authentication & trust

def test_unauthenticated_is_refused_by_default():
    cert = json.loads(json.dumps(valid_cases()["minimal_admitted"]))
    cert.pop("signature")
    from signoff_cert.fixtures import _seal
    sealed = _seal(cert)
    assert not verify_certificate(sealed).ok


def test_unauthenticated_may_be_allowed_explicitly_but_never_grades_authenticated():
    cert = json.loads(json.dumps(valid_cases()["minimal_admitted"]))
    cert.pop("signature")
    from signoff_cert.fixtures import _seal
    r = verify_certificate(_seal(cert), require_authentication=False)
    assert r.ok
    assert r.trust_level == "self-consistent"


def test_wrong_hmac_key_does_not_authenticate():
    r = verify_certificate(valid_cases()["minimal_admitted"], hmac_key=b"the wrong key")
    assert not r.ok
    assert r.trust_level != "authenticated"


def test_hmac_present_but_no_key_is_not_authenticated():
    r = verify_certificate(valid_cases()["minimal_admitted"], require_authentication=False)
    assert r.trust_level == "self-consistent"


def test_tampering_after_sealing_breaks_the_digest():
    r = verify_certificate(invalid_cases()["tampered_after_seal"], hmac_key=KEY)
    assert not r.ok
    assert any("mismatch" in x for x in r.reasons)


def test_copied_transparency_leaf_is_refused():
    r = verify_certificate(invalid_cases()["copied_ctlog_leaf"], hmac_key=KEY)
    assert not r.ok
    assert any("bind to THIS certificate" in x for x in r.reasons)


def test_self_signed_ed25519_is_self_consistent_not_authenticated():
    """The trap this format exists to close: anyone can generate a keypair. A signature checked
    against the key embedded beside it attests nothing about origin."""
    crypto = pytest.importorskip("cryptography", reason="Ed25519 authority path is optional")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from signoff_cert.fixtures import _seal

    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    cert = json.loads(json.dumps(valid_cases()["minimal_admitted"]))
    cert.pop("signature")
    cert = _seal(cert)
    rec = cert["digests"]["record_sha256"]
    cert["signature"] = {"alg": "Ed25519", "key_id": "self", "pubkey": pub,
                         "sig": sk.sign(rec.encode()).hex()}

    # No pinned key supplied: must NOT reach authenticated.
    r = verify_certificate(cert, require_authentication=False)
    assert r.trust_level == "self-consistent"

    # Pinned to the same key: now it is attributable.
    r2 = verify_certificate(cert, pinned_pubkey=pub)
    assert r2.ok and r2.trust_level == "authenticated"

    # Pinned to a DIFFERENT operator: refused.
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw).hex()
    assert not verify_certificate(cert, pinned_pubkey=other).ok


# ---------------------------------------------------------------- CLI

def test_cli_conform_reports_conformance(capsys):
    from signoff_cert.cli import main
    assert main(["conform"]) == 0
    assert "CONFORMING" in capsys.readouterr().out


def test_cli_verify_exits_nonzero_on_a_bad_certificate(tmp_path, capsys):
    from signoff_cert.cli import main
    p = tmp_path / "bad.cert.json"
    p.write_text(json.dumps(invalid_cases()["tighter_bound_than_evidence"]))
    assert main(["verify", str(p), "--allow-unauthenticated"]) == 1


def test_cli_verify_accepts_a_good_certificate(tmp_path):
    from signoff_cert.cli import main
    import os
    p = tmp_path / "good.cert.json"
    p.write_text(json.dumps(valid_cases()["minimal_admitted"]))
    os.environ["SC_TEST_KEY"] = KEY.decode()
    assert main(["verify", str(p), "--hmac-key-env", "SC_TEST_KEY"]) == 0


def test_cli_verify_reports_unreadable_input_rather_than_crashing(tmp_path, capsys):
    from signoff_cert.cli import main
    p = tmp_path / "nope.cert.json"
    p.write_text("{not json")
    assert main(["verify", str(p)]) == 1
    assert "unreadable" in capsys.readouterr().out


def test_cli_fixtures_writes_the_corpus(tmp_path):
    from signoff_cert.cli import main
    assert main(["fixtures", "--out", str(tmp_path)]) == 0
    written = list(tmp_path.rglob("*.cert.json"))
    assert len(written) == len(valid_cases()) + len(invalid_cases())


def test_cli_show_prints_the_scope(tmp_path, capsys):
    from signoff_cert.cli import main
    p = tmp_path / "c.cert.json"
    p.write_text(json.dumps(valid_cases()["minimal_admitted"]))
    main(["show", str(p)])
    assert "static co-batching" in capsys.readouterr().out
