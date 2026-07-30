"""signoff-cert — one receipt format, one reader, seven domains.

A signoff certificate is a self-describing JSON object asserting that a subject artifact was
admitted, rejected, or refused by a fail-closed gate -- and carrying, as REQUIRED machine-readable
fields, its own false-pass bound and the honest scope of that bound.

That last part is the whole point. Every CI badge in existence says "passed". None of them says
how often "passed" is wrong, or over what population the number holds. A certificate that carries
`false_pass_bound`, `bound_type` and `scope` can be compared, recomputed, and argued with.

This package is the REFERENCE READER. It verifies; it does not issue, admit, or refuse anything.
See CLAIMS-MAP.md for the line and why it matters.
"""
from __future__ import annotations

__version__ = "1.0.1"

from .bounds import clopper_pearson_upper, describe_bound, recompute, zero_observed_ceiling
from .canonical import canonical_bytes, content_sha256, semantic_sha256, sha256_hex
from .fixtures import invalid_cases, valid_cases
from .verify import DOMAINS, VERDICTS, VerifyResult, verify_certificate

__all__ = [
    "verify_certificate", "VerifyResult", "VERDICTS", "DOMAINS",
    "canonical_bytes", "sha256_hex", "semantic_sha256", "content_sha256",
    "recompute", "describe_bound", "clopper_pearson_upper", "zero_observed_ceiling",
    "valid_cases", "invalid_cases", "__version__",
]
