# `signoff-cert/v1` — normative specification

A **signoff certificate** is a self-describing JSON object asserting that a subject artifact was
admitted (or rejected/refused) by a fail-closed gate, carrying a machine-readable false-pass bound so
the certificate states its own trust. This document is normative: a third party MUST be able to
implement a conforming verifier from this text alone, without any certfabric source.

The key words MUST, MUST NOT, SHOULD, MAY are per RFC 2119.

## 1. Canonicalization

All hashing uses the single canonical serialization:

```
canonical_bytes(x) = json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=True, default=str)
sha256_hex(x)      = SHA-256(canonical_bytes(x)) as lowercase hex
```

A verifier MUST use exactly this convention. Any deviation (whitespace, key order, unicode escaping)
changes the digest and MUST cause verification to fail.

## 2. Object shape

A certificate is a JSON object with these top-level keys:

| key | required | meaning |
|---|---|---|
| `schema` | yes | MUST be the string `"signoff-cert/v1"` |
| `domain` | yes | one of `litho, em-signoff, zk-hw, code-rewrite, wifi-pqc, telecom, kv-isolation` |
| `subject` | yes | `{ "id": str, "artifact_digests": { "<name>": "<sha256>" } }` |
| `claim` | yes | `{ "property": str, "predicate"?: <bounded AST §5> }` |
| `verdict` | yes | one of `ADMITTED, REJECTED, REFUSED` (tri-state; **REFUSED is the fail-closed default**) |
| `gate` | yes | `{ "name": str, "provenance": str, "legs": { "<leg>": bool } }` |
| `confidence` | yes | the confidence block, §4 |
| `evidence` | no | inputs a verifier needs to recompute the confidence bound (e.g. `k`, `n`, `eval_stream`) |
| `honesty` | no | `{ "proven": [], "simulated": [], "aspirational": [], "non_claims": [] }` |
| `digests` | yes | `{ "semantic_sha256": str, "record_sha256": str }`, §3 |
| `signature` | no | §6 |
| `attestation` | no | in-toto Statement v1 envelope, §7 |
| `provenance` | no | `{ "content_sha256": str, "git_commit"?, "sealed_utc"?, "ots_anchor"?, "ctlog_leaf"? }` |

## 3. Digests (the dual-digest rule)

- `semantic_sha256 = sha256_hex({schema, domain, claim})` — the MEANING of the claim. Two
  certificates asserting the same thing about the same domain share this digest regardless of gate
  internals, timestamps, or signer.
- `content_sha256` / `record_sha256 = sha256_hex(body')` where `body'` is the certificate with
  `signature`, `attestation`, `digests`, `provenance.content_sha256`, and `provenance.ctlog_leaf`
  removed. This is a fixed point: sealing then recomputing yields the same value.

A verifier MUST recompute both and reject on any mismatch.

## 4. Confidence block (the differentiator)

```jsonc
{
  "method": "<one admitted method>",
  "false_pass_bound": <float>,     // machine-readable bound; its MEANING is given by bound_type
  "bound_type": "false_pass_rate_upper | miscoverage_upper | risk_upper | mean_lower | uncertifiable_at_n | tail_probability_upper",
  "coverage_level": <float>,       // 1 - alpha (or 1 - delta)
  "ci": [<lo>, <hi>],
  "n_samples": <int>, "delta": <float>,
  "machine_checked": <bool>,       // true iff coverage is a checked Lean theorem
  "paper": "<citation>",
  "scope": "<honest scope, verbatim from the source>"
}
```

`bound_type` is REQUIRED so the number is never mistaken for something it isn't. Not every method
produces a false-pass *rate*: `empirical-bernstein` produces `mean_lower` (a lower confidence bound on
a bounded performance mean), `impossibility-floor` produces `uncertifiable_at_n` (the property cannot
be certified at this sample size). A verifier MUST NOT treat a `mean_lower` or `uncertifiable_at_n`
bound as if it were a `false_pass_rate_upper`.

Admitted `method` values and their meaning:

| method | `false_pass_bound` is | paper |
|---|---|---|
| `clopper-pearson` | exact binomial upper tail on `k/n` | Clopper-Pearson 1934 |
| `anytime` / `betting-cs` | anytime-valid Ville e-process UCB | Waudby-Smith & Ramdas 2024 |
| `split-conformal-band` | miscoverage `alpha`; `ci=[1-alpha, 1-alpha+1/(n+1)]` | Vovk / Lei 2018 |
| `conformal-risk-control` | CRC risk bound | Angelopoulos-Bates 2024 |
| `rcps` | risk `alpha` at confidence `1-delta` | Bates et al. 2021 |
| `learn-then-test` | family-wise valid risk | Angelopoulos et al. |
| `empirical-bernstein` | one-sided lower bound on a bounded mean | Maurer-Pontil 2009 |
| `exhaustive-model-count` | `0.0` iff 0 counterexamples over the full finite domain | exact enumeration |
| `impossibility-floor` | `1.0` (property uncertifiable at this n) | capacity/query lower bound |
| `evt-tail` | EVT peaks-over-threshold tail probability | Pickands-Balkema-de Haan |

A verifier SHOULD recompute `false_pass_bound` from `evidence` using the named method and reject if
the recorded bound is tighter than the recomputed one beyond floating tolerance. Where the raw stream
is not carried inline the verifier MUST report the bound as "not independently rechecked" rather than
treat it as verified.

## 5. Bounded claim predicate (optional, machine-checkable)

`claim.predicate`, when present, is a typed expression over finite-domain variables (int ranges,
bit-vectors ≤256, arrays ≤16). Operators: arithmetic, (un)signed comparisons, boolean connectives,
`ite`, `select`. A verifier that supports predicates MUST re-decide it by exhaustive finite
evaluation and reject if the decided verdict differs from `predicate.expected`. Anything outside this
fragment MUST raise, never be treated as a proof (no lemma-smuggling).

## 6. Signature

`signature = { "alg": "HMAC-SHA256"|"Ed25519", "key_id", "sig", "pubkey"? }`, computed over
`content_sha256` (never the whole object). The **authority path MUST use Ed25519 verified against an
out-of-band pinned operator public key** and reject the pubkey the signer embeds. An unsigned
certificate is tamper-evident but not authenticated; a verifier MAY require a signature.

## 7. Attestation & transparency

`attestation` is an in-toto Statement v1 whose primary subject digest equals `content_sha256`. The
optional `provenance.ctlog_leaf = { log_id, index, leaf_hash, inclusion_proof }` binds the
certificate into an RFC-6962 transparency log; a verifier with a published STH MUST verify inclusion.

## 8. Verifier algorithm (fail-closed, default-strict)

Each REQUIRED step MUST pass or the effective verdict becomes `REFUSED`. The verifier MUST NOT raise
on malformed input — any internal error collapses to `REFUSED`. It MUST reject an over-nested
certificate before hashing (a DoS guard) and MUST treat an unknown `verdict`, `domain`, or confidence
`method` as a hard failure, never a silent admit.

0. Structural validity (§2), including finite `false_pass_bound` and a depth bound.
1. Recompute `semantic_sha256`, `record_sha256`, `content_sha256`; compare.
2. Re-run the gate; reproduced verdict MUST equal the recorded verdict. If a bounded predicate is
   present, re-decide it (§5). **Honest limitation:** the gate `legs` and `evidence` are
   producer-authored, so a domain-free replay checks verdict↔legs *consistency*; attesting the legs
   are real requires the domain's actual gate (a supplied `gate_rerun`) or the faucet's
   differential-equivalence certificate.
3. Recompute `confidence.false_pass_bound` from `evidence` (§4), INCLUDING the finite-sample
   feasibility floor: e.g. a split-conformal miscoverage below `1/(n+1)` is INFEASIBLE, not merely
   optimistic, and MUST be refused. An `exhaustive-model-count` bound of `0.0` is valid ONLY with a
   true `enumerated ≥ state_space`.
4. **Authentication (default-required):** a certificate is AUTHENTICATED only via HMAC verified with
   a supplied key, or Ed25519 verified against a PINNED operator key. An Ed25519 signature verified
   against its own *embedded* pubkey is self-consistent, NOT authenticated. By default a certificate
   that is not authenticated is not admissible.
5. Verify the in-toto `attestation` binding (§7).
6. If a `ctlog_leaf` is present, its `leaf_hash` MUST bind to THIS certificate
   (`== leaf_hash_for_cert(cert)`) and then be proven included under a published STH. A leaf copied
   from another certificate MUST fail.

The verifier also grades a `trust_level`: `unverified < self-consistent < authenticated < anchored`.
`ok` is the fail-closed policy decision; `trust_level` reports how far the certificate got.
