# CLAIMS-MAP — signoff-cert

**Tag: CLEAN. Licence: Apache-2.0.**

This file exists so the CLEAN tag is *auditable* rather than asserted.

## The line

Every method independent claim in the corresponding filed specification terminates in a
**physical actuation** step. For the family this package approaches, that step is:

> *"…emitting a certificate binding the recomputed value and **writing bytes of a unit of
> computed state into a memory region of the relying party's environment, or refusing to write
> them** …"*

and, for the transparency family:

> *"…recording the recomputed root value … and **refusing to admit a gate decision** in reliance
> on the evidence set."*

`signoff-cert` **reads**. It parses a certificate, recomputes digests and bounds, and prints a
verdict. It writes nothing into any relying party's environment, admits nothing, and refuses
nothing beyond its own exit code.

## Claims approached, and the step not performed

| Filed claim family | What it recites | What signoff-cert does instead |
|---|---|---|
| Certificate issuance + transparency anchoring | *(a)* compute a bound over an evidence set; *(b)* bind it into a record with a canonical digest; *(c)* anchor the record in a transparency log; **(d) write the attested unit of state into the relying party's environment, or refuse to write it** | Performs the *verification duals* of (a)–(c): recomputes the bound, recomputes the digests, checks leaf binding. Never performs (d). There is no write path and no relying-party environment in this package. |
| Evidence-backed admission gating | maintaining an evidence set backing an admission gate, recomputing a root over it, and **refusing to admit a gate decision** in reliance on it | Recomputes and reports. `verify_certificate` returns a dataclass. The CLI's exit code is a reporting convention, documented as such in `cli.py`, and gates nothing. |
| Issuing at scale (the faucet) | provisioning a service that issues certificates into the format under an operator key | Out of scope entirely. **Reading is free; issuing at scale is the product.** |

## The distinction, stated plainly

A verifier that *reports* `REFUSED` does not practice these claims. A verifier wired so that its
`REFUSED` blocks a deployment, withholds bytes, or gates an operation on a physical resource
**does**, because that wiring supplies the terminal step the claim recites.

This is a property of **how the tool is wired, not of this repository's intentions**, which is
why it is mechanically enforced rather than promised: `oss/tools/check_measure_only.py` fails the
build if any CLEAN-tagged artifact grows an actuation path.

## Non-claims

- Verifying a certificate is not a claim that the underlying gate ran, or ran honestly. §8.2 and
  the README both say this; a domain-free replay checks verdict↔legs consistency only.
- A `trust_level` of `authenticated` attests the signer held the key. It attests nothing about
  whether the signer's measurement was competent.
