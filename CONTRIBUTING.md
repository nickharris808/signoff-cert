# Contributing to signoff-cert

## The one rule

**This package reads. It never gates.**

A pull request that makes the verifier block a deploy, withhold an artifact, gate an operation
on a physical resource, or write into a relying party's environment will be declined — not for
style reasons, but because it changes the artifact's licence classification. See
[`CLAIMS-MAP.md`](CLAIMS-MAP.md). CI enforces this via `check_measure_only.py`.

If you want gating behaviour, wire this verifier's *output* into your own gate in your own repo.
That is a supported and expected use; it is simply not something this package does for you.

## Changing the canonical form is a breaking change to every certificate ever sealed

`canonical.py` fixes one serialization: `sort_keys=True, separators=(",",":"),
ensure_ascii=True, default=str`. Changing any of those kwargs silently invalidates every
previously sealed certificate — the digests will no longer reproduce. They are not configurable
and must not become configurable.

## Adding a confidence method

1. Add it to `METHODS` in `bounds.py` and to the enum in `schema/signoff-cert-v1.schema.json`.
2. Implement its recomputation in `bounds.recompute()`. If the raw stream cannot be carried
   inline, return `(None, None)` — the verifier will report *"not independently rechecked"*,
   which is honest. **Do not return a plausible-looking number you did not compute.**
3. State its **finite-sample feasibility floor** if it has one. A bound below that floor must be
   refused as *unreachable*, not flagged as *optimistic*. This is the single most valuable thing
   the format does; a method added without its floor weakens the whole standard.
4. Add a `valid/` fixture and, where a floor exists, an `invalid/` one that violates it.

## Adding a conformance fixture

Each fixture must isolate **exactly one** defect. A fixture that breaks two rules cannot tell an
implementer which one their verifier missed, which defeats the purpose of the corpus.

Prefer defects a *naive verifier passes*. A fixture with a corrupted digest is nearly worthless —
everyone catches that. A fixture whose digests, signature and structure are all impeccable and
whose only flaw is a bound its own evidence does not support is worth ten of them.

## Tests

```bash
pip install -e ".[dev,crypto]"
python -m pytest -q                 # 53 tests
signoff-cert conform                # the corpus, end to end
```

Every test must plant a specific defect and assert the rule fires. A test that only asserts the
happy path passes is not evidence the check works — this is the failure class the sibling
`honestbench` package exists to measure, and we are not exempt from it.
