# signoff-cert

**Every CI badge says "passed". None of them says how often "passed" is wrong.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](pyproject.toml)

`signoff-cert/v1` is a certificate format in which the **false-pass bound and its scope are
required machine-readable fields**. A certificate that cannot state how often it is wrong, and
over what population, does not validate.

This package is the **reference reader**: a dependency-free verifier, a JSON Schema, and a
16-case conformance corpus that any third-party implementation can be checked against.

**Not yet on PyPI.** The command below is the one that works today. It installs from this repository, pinned to a tag.

```bash
pip install "git+https://github.com/nickharris808/signoff-cert@v1.0.1"
```

`pip install signoff-cert` is the intended command once the name is published. **It 404s today**, which is why it is not the first step above. The tag is pinned rather than `@main` so a reader installs the exact code this README documents.

## Why a bound is a required field

A green check mark is a claim with no error bar. In practice the interesting question is never
"did it pass" but "what would it take for this to have passed while being wrong" — and that
question has a number, which almost nobody publishes.

So the format requires three things a normal badge omits:

| field | why it is required |
|---|---|
| `false_pass_bound` | the probability the verdict is wrong, as a number |
| `bound_type` | **what kind** of number it is — a rate, a lower bound on a mean, or "uncertifiable at this n" |
| `scope` | the population it holds over, verbatim from the source |

`bound_type` exists because not every method produces a false-pass *rate*. An
`empirical-bernstein` bound of `0.87` is a **lower bound on a performance mean** — excellent.
Read as a failure rate it is a disaster. An `impossibility-floor` bound of `1.0` means *the
property cannot be certified at this sample size* — an honest, useful statement that reads as
catastrophic if you mistake it for a rate. A verifier that compares across bound types is
worse than one that reports nothing.

## Install

> **Not yet on PyPI.** `pip install signoff-cert` is the intended install once published;
> until then install from the repository — it works exactly the same:
>
> ```
> pip install git+https://github.com/nickharris808/signoff-cert@main
> ```

```bash
pip install signoff-cert            # integrity path: zero dependencies
pip install "signoff-cert[crypto]"  # adds the Ed25519 authority path
```

## 30-second quickstart

```bash
# Is this certificate real, and what does it actually claim?
signoff-cert verify build.cert.json --hmac-key-env SIGNOFF_KEY

# What does it say, in English?
signoff-cert show build.cert.json

# Is MY verifier conforming? Write the corpus and run it against yours.
signoff-cert fixtures --out fixtures/
signoff-cert conform
```

## Worked example

```console
$ signoff-cert verify fixtures/valid/minimal_admitted.cert.json --hmac-key-env SIGNOFF_KEY
[ok] fixtures/valid/minimal_admitted.cert.json
       verdict ....... ADMITTED
       trust ......... authenticated
       bound ......... false-pass probability at most 0.029513 (false_pass_rate_upper)
       scope ......... one engine build, one GPU class; static co-batching only
       recomputed .... 0.029513 (independently rechecked)
```

Note the last line. The verifier did not take the producer's word for the bound — it recomputed
it from the `evidence` block (`k=0, n=100`) and confirmed the recorded value is not tighter than
what that record supports. Now the same certificate with the bound quietly improved:

```console
$ signoff-cert verify fixtures/invalid/tighter_bound_than_evidence.cert.json --hmac-key-env SIGNOFF_KEY
[FAIL] fixtures/invalid/tighter_bound_than_evidence.cert.json
       verdict ....... REFUSED
       trust ......... authenticated
       bound ......... false-pass probability at most 0.001 (false_pass_rate_upper)
       scope ......... one engine build, one GPU class; static co-batching only
       recomputed .... 0.029513 (independently rechecked)
       - recorded bound 0.001 is TIGHTER than the recomputed 0.029513: the evidence does not support the claimed confidence
```

Every digest matches. The signature verifies. The certificate is authentic and internally
consistent — and the claim is still false, because 0 failures in 100 trials does not support a
one-in-a-thousand bound. **Only a verifier that recomputes catches this**, which is why §8.3
makes recomputation required rather than optional.

## The conformance corpus

A spec with one implementation is a library. A spec with a corpus that every conforming verifier
must accept and reject is a standard.

```console
$ signoff-cert conform
CONFORMING — 5 accepted, 11 refused, as required.
```

The 11 refusals are deliberately the cases a naive verifier passes:

| fixture | the defect |
|---|---|
| `tighter_bound_than_evidence` | claims more confidence than its own k/n supports |
| `rounded_bound_tighter` | bound printed to 4 dp — **rounding a bound down claims confidence you don't have** |
| `conformal_below_floor` | miscoverage below `1/(n+1)`: not optimistic, arithmetically unreachable |
| `partial_enumeration_zero` | a `0.0` "exhaustive" bound over a partial enumeration |
| `copied_ctlog_leaf` | a valid transparency leaf lifted from a different certificate |
| `missing_bound_type` | a bare number whose meaning is undefined |
| `admitted_with_failed_leg` | verdict `ADMITTED` while a gate leg is false |
| `tampered_after_seal` | one field edited after sealing |
| `over_nested` | a depth bomb — refused **before** hashing |
| `unknown_domain` / `unknown_verdict` | unknown enum treated as a hard failure, never a silent admit |

`rounded_bound_tighter` is the one worth stealing. Everything about that certificate is
impeccable except that the producer printed `%.4f` of `0.02951304959…` and got `0.0295` — very
slightly *tighter* than the truth. It is the most likely way a real, well-intentioned producer
emits an unsupportable bound.

## Trust levels — `ok` is not the whole story

```
unverified  <  self-consistent  <  authenticated  <  anchored
```

`ok` is the policy decision; `trust_level` reports how far the certificate actually got. The
distinction that matters: **an Ed25519 signature checked against the public key embedded in the
same certificate proves nothing about origin.** Anyone can generate a keypair and sign anything.
That grades `self-consistent`. Reaching `authenticated` requires a key you hold out of band — an
HMAC secret, or a *pinned* operator public key. Collapsing those two states is the most common
way a signature check becomes decorative.

## Fail-closed, always

The verifier **never raises**. Malformed input, a depth bomb, an exploding gate re-runner — all
collapse to `REFUSED`. This is not defensive politeness; a verifier that throws is one a hostile
producer can turn into an outage, and a caller who wraps it in `try/except: pass` has silently
converted a fail-closed gate into an admit-by-default one.

```python
from signoff_cert import verify_certificate

r = verify_certificate(cert, hmac_key=key)
r.ok                 # the policy decision
r.effective_verdict  # ADMITTED / REJECTED / REFUSED
r.trust_level        # how far it got
r.reasons            # why, in English, for every failed check
```

## GitHub Action

```yaml
- uses: ./.github/actions/signoff-cert
  with:
    path: '**/*.cert.json'
    hmac-key: ${{ secrets.SIGNOFF_KEY }}
```

Verifies every certificate in the PR and writes a job summary carrying each one's bound and
scope — so a reviewer sees the error bar, not just a tick.

## The commercial edition

This package is the **reference reader**. Reading and verifying a certificate performs none of the
steps the filed claims recite — see [`CLAIMS-MAP.md`](CLAIMS-MAP.md).

**Issuing** into the format at scale — the faucet, the hosted transparency log, and the anchoring
service — is the licensed offering.

**Reading is free. Issuing at scale is the product.**

## Honest limits

- **A domain-free replay checks verdict↔legs *consistency*, not that the legs are real.** The
  `gate.legs` and `evidence` blocks are producer-authored. Attesting they reflect a real gate run
  requires that domain's actual gate, supplied via `gate_rerun=`. The verifier says so in its
  output rather than letting a green tick imply more than it checked.
- **Bounds are only rechecked when the evidence is carried inline.** Where it is not, the result
  says *"not independently rechecked"* — which is not the same as verified, and is not reported
  as though it were.
- **This package verifies. It does not issue.** See [`CLAIMS-MAP.md`](CLAIMS-MAP.md).
- **The corpus is 16 cases, not a proof.** A verifier that passes has been shown to handle these
  sixteen defects. It has not been shown correct.

## Specification

[`spec/signoff-cert-v1.md`](spec/signoff-cert-v1.md) is normative and self-contained: a third
party can implement a conforming verifier from that text alone, without reading this code. The
JSON Schema is at [`schema/signoff-cert-v1.schema.json`](schema/signoff-cert-v1.schema.json).

## Licence

Apache-2.0. See [`LICENSE-TAG`](LICENSE-TAG) for the CLEAN classification and
[`CLAIMS-MAP.md`](CLAIMS-MAP.md) for the claim ranges this reader approaches and the terminal
step it does not perform.

<!-- HONEST-SCOPE -->
## Honest scope — what a passing run proves, and what it does not

The two halves are inseparable. A tool that states only the first half is marketing.

**It proves:**

- the certificate is internally consistent and unmodified since it was sealed
- its false-pass bound is not TIGHTER than its own recorded evidence supports (recomputed, not trusted)
- how far the trust chain got: unverified < self-consistent < authenticated < anchored

**It does NOT prove:**

- that the bound is CORRECT — only that it is supported by the evidence in the certificate. A producer measuring the wrong thing produces a valid certificate about the wrong thing
- that the producer is who they claim, unless you supplied a key you hold out of band. An Ed25519 signature checked against a key embedded in the same certificate proves nothing about origin
- anything about certificates it never saw

Full CLI reference, generated from `--help`: [`docs/CLI.md`](docs/CLI.md)
<!-- /HONEST-SCOPE -->

## Contributing

Bug reports and pull requests welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

**A false accusation is a defect of equal severity to a missed detection.** If this tool flags something correct, open an issue with the input and the verdict you expected: over-refusal trains people to bypass refusals, which destroys the tool.

Citation metadata is in [CITATION.cff](CITATION.cff).

<!-- PORTFOLIO -->
---

## The rest of the portfolio

25 artifacts, one idea: **a measurement you cannot check is a press release.** Every tool
here reports; none of them gates.

**Tools**

| | |
|---|---|
| [`abstain-bench`](https://github.com/nickharris808/abstain-bench) | how often does a verifier pass input it could not check? |
| [`evidence`](https://github.com/nickharris808/evidence) | run the whole portfolio over your repo — the weakest leg, never the mean |
| [`floorgen`](https://github.com/nickharris808/floorgen) | what must your system remember? an exact lower bound |
| [`formal-proof-mcp`](https://github.com/nickharris808/formal-proof-mcp) | a proof kernel for your coding agent |
| [`gatecount`](https://github.com/nickharris808/gatecount) | exactly how many states does removing this check admit? |
| [`gridlock`](https://github.com/nickharris808/gridlock) | certify a wait-for relation cannot wedge |
| [`honestbench`](https://github.com/nickharris808/honestbench) | measure your CI's escape rate |
| [`kvleak`](https://github.com/nickharris808/kvleak) | cross-tenant leak scanner |
| [`kvprobe`](https://github.com/nickharris808/kvprobe) | model-substitution detector with a measured FPR |
| [`preregister`](https://github.com/nickharris808/preregister) | refuses to seal a plan whose conclusion is already fixed |
| [`proof-carrying-ci`](https://github.com/nickharris808/proof-carrying-ci) | the whole portfolio as one CI check, with SARIF |
| [`proof-to-code-drift`](https://github.com/nickharris808/proof-to-code-drift) | fail the build when the proof stops matching |
| [`sf-verify`](https://github.com/nickharris808/sf-verify) | re-derive admission decisions offline |
| [`signoff-cert`](https://github.com/nickharris808/signoff-cert) | certificates that carry their own false-pass bound ← you are here |
| [`tokencount`](https://github.com/nickharris808/tokencount) | a token count both parties can recompute |

**Benchmarks** — each recomputes one of our own published numbers from its certificate

| | |
|---|---|
| [`illusion-bench`](https://github.com/nickharris808/illusion-bench) | how many broken kernels does your oracle admit? |
| [`kv-reuse-econ-bench`](https://github.com/nickharris808/kv-reuse-econ-bench) | recompute our economics headline |
| [`llm-tenant-isolation-bench`](https://github.com/nickharris808/llm-tenant-isolation-bench) | recompute our isolation figures |

**Datasets**

| | |
|---|---|
| [`abstain-corpus`](https://huggingface.co/datasets/nickh007/abstain-corpus) | 32 inputs a verifier must NOT pass |
| [`kv-reuse-econ-traces`](https://huggingface.co/datasets/nickh007/kv-reuse-econ-traces) | per-workload reuse accounting + the closed form |
| [`kv-tenant-isolation-bench`](https://huggingface.co/datasets/nickh007/kv-tenant-isolation-bench) | isolation observations, uninterpretable rows included |
| [`llm-precision-fingerprints`](https://huggingface.co/datasets/nickh007/llm-precision-fingerprints) | precision-labelled logprobs with a negative control |

**Try it in a browser** — no install, no GPU

| | |
|---|---|
| [`negative-results-atlas`](https://huggingface.co/spaces/nickh007/negative-results-atlas) | ten claims we took back |
| [`tenant-leak-demo`](https://huggingface.co/spaces/nickh007/tenant-leak-demo) | the residency calculator |
| [`wait-for-visualiser`](https://huggingface.co/spaces/nickh007/wait-for-visualiser) | paste a wait-for graph, see the cycle |

### Documentation

Everything above, explained in one place: **<https://nickharris808.github.io/evidence-docs/>** —
the [tutorial](https://nickharris808.github.io/evidence-docs/start/tutorial/),
[what this proves and what it does not](https://nickharris808.github.io/evidence-docs/concepts/what-this-proves/),
and a [CLI reference](https://nickharris808.github.io/evidence-docs/reference/cli/) generated by
running `--help` on every published command.

### The commercial edition

Everything above is **measure-only** and Apache-2.0: it tells you what is true and never acts on
it. The **enforcement** side — binding a partition key at the admission decision, the compiled gate
corpus, and the certificate-*issuing* faucet — is covered by filed patents and licensed separately.

**Reading is free. Enforcing is licensed.**
<!-- /PORTFOLIO -->
