"""Cryptographic cost model for THREAT-MODEL.md §4.

`commit_hash` and `vrf_seed` remain fast stand-ins deliberately: exp1,
exp2, exp4, and exp5 draw tens of thousands of samples each, and their
security conclusions (win rates, slot shares) depend only on the
sampling seed's *statistical* independence across tasks, not on it
being a real cryptographic beacon for every single draw. Running real
threshold-BLS for every one of those draws would add real time for no
change in result -- see threshold_bls.py's module docstring for the
actual, correctness-verified k-of-m implementation these are standing
in for.

`threshold_decrypt_latency_ms`, by contrast, is not a guess. Its
constants come from experiments/exp7_real_threshold_bls_benchmark.py,
which benchmarks threshold_bls.py's real BLS12-381 implementation under
a parallel-committee latency model (members sign concurrently;
client-facing cost ~= one member's partial-sign time + the aggregator's
combine step -- see threshold_bls.py's benchmark_parallel_latency_ms
docstring for why that model, not a sequential sum over k, is the
realistic one).

This number has a real history worth keeping, not smoothing over:
  1. First draft: base_ms=5.0, per_share_ms=1.5 -- a guess, never
     benchmarked against anything.
  2. Benchmarked against py_ecc (pure-Python BLS12-381 reference
     implementation): base_ms=239.08, per_share_ms=33.47 -- ~30-40x
     higher than the guess. Correct crypto, but py_ecc is a spec-
     conformance reference, not built for speed, and that gap mattered:
     it flipped exp3's "small latency tax" conclusion to "26-47% of
     end-to-end task latency," which needed to be reported honestly
     rather than left as a guess-based claim.
  3. Rebenchmarked against `py_arkworks_bls12381` (Rust
     arkworks bindings, prebuilt wheel -- no C++ toolchain needed on
     this machine, unlike the `blspy` build that failed here). Real
     numbers: base_ms=3.06, per_share_ms=0.27 -- roughly 100x faster
     than the py_ecc measurement, and back in the same ballpark as the
     original guess (by coincidence, not because the guess was
     principled). These were later refit (see 4).
  4. Current: the linear fit of exp7's 500-trial parallel-committee medians, base_ms=0.68, per_share_ms=0.44.
     Timings move by up to 2x between runs on a loaded machine (an earlier run gave 3.06 and 0.27 under the
     same method), so treat the constants as order-of-magnitude, not as a hardware-independent result.

The three numbers above tell a real story: a guess can land anywhere,
a correctness-verified-but-unoptimized reference implementation can be
badly pessimistic, and only a production-shaped backend gives a number
worth citing in a latency claim. All three are kept in exp7's output
and this docstring specifically so nobody downstream mistakes "we
benchmarked something" for "we benchmarked the right thing" -- that
distinction is what changed the answer twice here.
"""
import hashlib


def commit_hash(query_repr: str, nonce: str) -> str:
    return hashlib.sha256((query_repr + nonce).encode()).hexdigest()


def vrf_seed(task_commit_hash: str, committee_nonce: str) -> int:
    """Fast stand-in for threshold_bls.beacon_seed() -- see module
    docstring for why the statistical experiments use this instead of
    the real (correctness-verified, and now genuinely fast) primitive
    for every one of their many draws."""
    h = hashlib.sha256((task_commit_hash + committee_nonce).encode()).hexdigest()
    return int(h, 16)


def threshold_decrypt_latency_ms(k: int, m: int, base_ms: float = 0.68,
                                  per_share_ms: float = 0.44) -> float:
    """Latency model for a k-of-m threshold operation, fitted from real
    measurements against the arkworks-backed implementation (see module
    docstring and exp7). Linear in k because that's what the
    parallel-committee model's aggregation (combine()) cost actually
    does on real measurement -- not assumed a priori."""
    return base_ms + per_share_ms * k
