"""signoff_cert.bounds — recompute the certificate's own false-pass bound.

WHY A VERIFIER RECOMPUTES THIS. The differentiating field of `signoff-cert/v1` is that the
certificate carries its own false-pass bound. A bound nobody checks is a decoration, so §8.3
requires the verifier to recompute it from `evidence` and refuse a certificate whose recorded
bound is TIGHTER than the recomputed one -- i.e. a producer claiming more confidence than its
own evidence supports.

Two things here are easy to get wrong and both are load-bearing:

  * `bound_type` is REQUIRED (§4). A `mean_lower` is a lower bound on a performance mean; an
    `uncertifiable_at_n` says the property cannot be certified at this n at all. Neither is a
    false-pass RATE, and treating them as one reads a 1.0 ("cannot certify") as catastrophic
    or a 0.02 ("mean at least 2%") as excellent. The verifier must never compare across types.

  * The FINITE-SAMPLE FEASIBILITY FLOOR. A split-conformal miscoverage below 1/(n+1) is not
    merely optimistic -- it is arithmetically unreachable at that sample size. Likewise an
    exhaustive model count of 0.0 is meaningless unless the enumeration actually covered the
    state space. These are refusals, not warnings.

Stdlib only: the regularized incomplete beta is implemented here by continued fraction so the
package keeps a zero-dependency install and a small reviewable surface.
"""
from __future__ import annotations

import math
from typing import Any, Mapping, Optional, Tuple

# bound_type values that denote an upper bound on a false-pass PROBABILITY. Only these are
# comparable with one another; see the module docstring.
RATE_LIKE = ("false_pass_rate_upper", "miscoverage_upper", "risk_upper", "tail_probability_upper")

BOUND_TYPES = RATE_LIKE + ("mean_lower", "uncertifiable_at_n")

METHODS = ("clopper-pearson", "anytime", "betting-cs", "split-conformal-band",
           "conformal-risk-control", "rcps", "learn-then-test", "empirical-bernstein",
           "exhaustive-model-count", "impossibility-floor", "evt-tail")


# --- regularized incomplete beta, for the exact binomial tail --------------------------------

def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta (Lentz's method)."""
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3e-16:
            break
    return h


def betai(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
             + a * math.log(x) + b * math.log1p(-x))
    if x < (a + 1.0) / (a + b + 2.0):
        return math.exp(lbeta) * _betacf(a, b, x) / a
    return 1.0 - math.exp(lbeta) * _betacf(b, a, 1.0 - x) / b


def clopper_pearson_upper(k: int, n: int, conf: float = 0.95) -> float:
    """Exact (Clopper-Pearson) one-sided upper bound on a rate given k events in n trials.

    Exact means it inverts the binomial CDF rather than assuming normality, so coverage is at
    least nominal at every n -- conservative, never optimistic. That is the right direction for
    a false-pass bound: we would rather overstate our uncertainty than understate it.
    """
    if n <= 0 or k < 0 or k > n:
        raise ValueError(f"invalid record k={k} n={n}")
    if k == n:
        return 1.0
    # The upper limit is the rate p at which P[X <= k | p] = 1 - conf. Using the standard
    # binomial/beta identity P[X <= k | p] = 1 - I_p(k+1, n-k), that is the p solving
    #     I_p(k + 1, n - k) = conf
    # I_p is monotonically increasing in p, so bisect on it directly.
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if betai(k + 1, n - k, mid) > conf:
            hi = mid
        else:
            lo = mid
    return hi


def zero_observed_ceiling(n: int, conf: float = 0.95) -> float:
    """The bound a CLEAN record supports. 0 events in n trials still permits a rate this high."""
    return clopper_pearson_upper(0, n, conf)


# --- the recompute path ----------------------------------------------------------------------

def recompute(cert: Mapping[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    """Recompute the bound from `evidence`. Returns (bound, infeasibility_reason).

    A non-None reason means the recorded bound is not merely optimistic but ARITHMETICALLY
    UNREACHABLE at the stated sample size, which §8.3 requires be refused outright.
    """
    conf_block = cert.get("confidence") or {}
    method = conf_block.get("method")
    ev = cert.get("evidence") or {}
    if not isinstance(ev, Mapping):
        return None, None

    if method == "clopper-pearson":
        k, n = ev.get("k"), ev.get("n")
        if isinstance(k, int) and isinstance(n, int) and n > 0 and 0 <= k <= n:
            level = conf_block.get("coverage_level")
            conf = float(level) if isinstance(level, (int, float)) and 0 < level < 1 else 0.95
            return clopper_pearson_upper(k, n, conf), None
        return None, None

    if method == "split-conformal-band":
        n = ev.get("n") or conf_block.get("n_samples")
        recorded = conf_block.get("false_pass_bound")
        if isinstance(n, int) and n > 0:
            floor = 1.0 / (n + 1)
            if isinstance(recorded, (int, float)) and recorded < floor - 1e-12:
                return floor, (
                    f"split-conformal miscoverage {recorded:g} is below the finite-sample floor "
                    f"1/(n+1) = {floor:g} at n={n}: not optimistic, UNREACHABLE")
            return recorded if isinstance(recorded, (int, float)) else None, None
        return None, None

    if method == "exhaustive-model-count":
        enumerated, space = ev.get("enumerated"), ev.get("state_space")
        recorded = conf_block.get("false_pass_bound")
        if isinstance(enumerated, int) and isinstance(space, int):
            if enumerated >= space:
                return 0.0, None
            if isinstance(recorded, (int, float)) and recorded <= 0.0:
                return None, (
                    f"exhaustive-model-count claims 0.0 having enumerated {enumerated:,} of "
                    f"{space:,} states: a zero over a partial enumeration is a sampling result "
                    f"wearing an exhaustive label")
        return None, None

    if method == "impossibility-floor":
        return 1.0, None                       # the property is uncertifiable at this n, by construction

    # Methods whose raw stream is not carried inline cannot be rechecked here. The verifier
    # reports that honestly rather than treating "not rechecked" as "verified" (§4).
    return None, None


def describe_bound(conf_block: Mapping[str, Any]) -> str:
    """One line a human can read without misreading the number's direction."""
    b, t = conf_block.get("false_pass_bound"), conf_block.get("bound_type")
    if not isinstance(b, (int, float)):
        return "no bound recorded"
    if t == "mean_lower":
        return f"performance mean is at least {b:g} (a LOWER bound; not a failure rate)"
    if t == "uncertifiable_at_n":
        return f"property is UNCERTIFIABLE at this sample size (bound {b:g} is not a rate)"
    return f"false-pass probability at most {b:g} ({t})"


__all__ = ["betai", "clopper_pearson_upper", "zero_observed_ceiling", "recompute",
           "describe_bound", "BOUND_TYPES", "RATE_LIKE", "METHODS"]
