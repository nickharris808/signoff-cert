"""signoff_cert.cli — verify certificates from a terminal or a CI job.

    signoff-cert verify CERT [CERT...]     verify one or more certificates
    signoff-cert show CERT                 print what the certificate says, in English
    signoff-cert fixtures --out DIR        write the conformance corpus
    signoff-cert conform                   run the reference verifier against the corpus

EXIT CODES. `verify` exits non-zero when a certificate does not verify. That is a REPORTING
convention: this tool prints a verdict, and the caller decides what to do with it. It performs
no step of admitting or refusing an operation on any physical resource -- see CLAIMS-MAP.md.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from . import __version__
from .bounds import describe_bound
from .fixtures import hmac_key, invalid_cases, valid_cases
from .verify import verify_certificate

_MARK = {True: "ok", False: "FAIL"}


def _load(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _key_from_args(a) -> bytes | None:
    if getattr(a, "hmac_key_env", None):
        v = os.environ.get(a.hmac_key_env)
        if v is None:
            raise SystemExit(f"${a.hmac_key_env} is not set")
        return v.encode()
    if getattr(a, "hmac_key_file", None):
        with open(a.hmac_key_file, "rb") as fh:
            return fh.read().strip()
    return None


def _cmd_verify(a) -> int:
    key = _key_from_args(a)
    worst = 0
    # `--json` over N certificates used to print N indented objects back to back, which is not
    # valid JSON for N > 1 — every consumer past the first certificate got a parse error. The
    # results are collected and emitted as ONE envelope instead. A tool whose machine-readable
    # output cannot be machine-read is worse than one with no --json at all: it looks integrable.
    collected = []
    for path in a.certs:
        try:
            cert = _load(path)
        except Exception as e:
            if a.json:
                collected.append({"path": path, "ok": False, "unreadable": str(e)})
            else:
                print(f"[FAIL] {path}: unreadable ({e})")
            worst = 1
            continue
        r = verify_certificate(cert, hmac_key=key, pinned_pubkey=a.pinned_pubkey,
                               require_authentication=not a.allow_unauthenticated)
        if a.json:
            collected.append({"path": path, **r.as_dict()})
        else:
            print(f"[{_MARK[r.ok]}] {path}")
            print(f"       verdict ....... {r.effective_verdict}")
            print(f"       trust ......... {r.trust_level}")
            conf = cert.get("confidence") if isinstance(cert, dict) else {}
            if isinstance(conf, dict):
                print(f"       bound ......... {describe_bound(conf)}")
                if conf.get("scope"):
                    print(f"       scope ......... {conf['scope']}")
            if r.bound_rechecked:
                print(f"       recomputed .... {r.recomputed_bound:g} (independently rechecked)")
            else:
                print("       recomputed .... not independently rechecked")
            for reason in r.reasons:
                print(f"       - {reason}")
        if not r.ok:
            worst = 1

    if a.json:
        n_ok = sum(1 for c in collected if c.get("ok"))
        print(json.dumps({
            "artifact": "signoff_cert_verify",
            "n_certificates": len(collected),
            "n_ok": n_ok,
            # The envelope verdict is the WEAKEST certificate, not a tally: one certificate that
            # does not verify is not offset by nine that do.
            "verdict": "VERIFIED" if collected and n_ok == len(collected) else "FAILED",
            "exit_code": worst,
            "results": collected,
        }, indent=2))
    return worst


def _cmd_show(a) -> int:
    cert = _load(a.cert)
    conf = cert.get("confidence") or {}
    print(f"schema ....... {cert.get('schema')}")
    print(f"domain ....... {cert.get('domain')}")
    print(f"subject ...... {(cert.get('subject') or {}).get('id')}")
    print(f"claim ........ {(cert.get('claim') or {}).get('property')}")
    print(f"verdict ...... {cert.get('verdict')}")
    print(f"bound ........ {describe_bound(conf)}")
    print(f"method ....... {conf.get('method')}   n={conf.get('n_samples')}")
    print(f"scope ........ {conf.get('scope', '(none recorded)')}")
    honesty = cert.get("honesty") or {}
    for k in ("proven", "simulated", "aspirational", "non_claims"):
        vals = honesty.get(k) or []
        if vals:
            print(f"{k:<12} . {'; '.join(map(str, vals))}")
    return 0


def _cmd_fixtures(a) -> int:
    out = a.out
    for sub, cases in (("valid", valid_cases()), ("invalid", invalid_cases())):
        d = os.path.join(out, sub)
        os.makedirs(d, exist_ok=True)
        for name, cert in cases.items():
            with open(os.path.join(d, f"{name}.cert.json"), "w", encoding="utf-8") as fh:
                json.dump(cert, fh, indent=2, sort_keys=True)
        print(f"  {sub}: {len(cases)} fixture(s) -> {d}")
    print("\nA conforming verifier MUST accept every valid/ case and REFUSE every invalid/ one.")
    return 0


def _cmd_conform(a) -> int:
    """Run the reference verifier against the corpus. Any third-party verifier should be able to
    reproduce these two counts exactly."""
    key = hmac_key()
    bad = []
    print("conformance corpus — the reference verifier's own result\n")
    for name, cert in sorted(valid_cases().items()):
        r = verify_certificate(cert, hmac_key=key)
        if not r.ok:
            bad.append(("valid", name, r.reasons))
        print(f"  [{_MARK[r.ok]:>4}] valid/{name:<32} trust={r.trust_level}")
    for name, cert in sorted(invalid_cases().items()):
        r = verify_certificate(cert, hmac_key=key)
        # For invalid cases, REFUSING is the correct outcome.
        good = not r.ok
        if not good:
            bad.append(("invalid", name, ["verifier ACCEPTED a certificate it must refuse"]))
        print(f"  [{_MARK[good]:>4}] invalid/{name:<30} "
              f"{'refused: ' + r.reasons[0][:52] if r.reasons else ''}")
    print()
    if bad:
        print(f"NON-CONFORMING — {len(bad)} case(s) wrong:")
        for kind, name, reasons in bad:
            print(f"  {kind}/{name}: {reasons[:1]}")
        return 1
    print(f"CONFORMING — {len(valid_cases())} accepted, {len(invalid_cases())} refused, as required.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="signoff-cert",
                                 description="reference verifier for signoff-cert/v1 (measure-only)")
    ap.add_argument("--version", action="version", version=f"signoff-cert {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="verify one or more certificates")
    v.add_argument("certs", nargs="+")
    v.add_argument("--hmac-key-env", help="env var holding the shared HMAC key")
    v.add_argument("--hmac-key-file", help="file holding the shared HMAC key")
    v.add_argument("--pinned-pubkey", help="out-of-band Ed25519 operator public key (hex)")
    v.add_argument("--allow-unauthenticated", action="store_true",
                   help="check integrity only; the result is NOT attributable to anyone")
    v.add_argument("--json", action="store_true")
    v.set_defaults(fn=_cmd_verify)

    s = sub.add_parser("show", help="print what the certificate says, in English")
    s.add_argument("cert")
    s.set_defaults(fn=_cmd_show)

    f = sub.add_parser("fixtures", help="write the conformance corpus to disk")
    f.add_argument("--out", default="fixtures")
    f.set_defaults(fn=_cmd_fixtures)

    c = sub.add_parser("conform", help="run the reference verifier against the corpus")
    c.set_defaults(fn=_cmd_conform)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
