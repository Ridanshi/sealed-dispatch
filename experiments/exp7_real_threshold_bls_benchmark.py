"""Swaps crypto_stub.py's placeholder threshold-decryption cost model
for real measurements: correctness-check the threshold BLS
implementation, then benchmark actual wall-clock latency across the
same committee sizes exp3/exp4 use, and fit the linear cost model's
constants to what was actually measured instead of guessed numbers.

This is a genuinely important check, not a formality: the original
crypto_stub.py constants (base_ms=5.0, per_share_ms=1.5) were never
measured against anything. Running this experiment revealed they were
off by roughly two orders of magnitude relative to a correctness-
verified reference BLS12-381 implementation (py_ecc) -- see README.md
for the actual numbers and what that does to exp3's "small latency tax"
conclusion.

Important scope caveat, stated plainly: py_ecc is a pure-Python
REFERENCE implementation, used here because it is correctness-verified
against the IETF BLS spec, not because it is fast. A production
deployment would use an optimized library (e.g. a Rust/C-backed
threshold-BLS or the `blst` bindings), which are commonly 2-3 orders of
magnitude faster. Treat the numbers here as a defensible PESSIMISTIC
upper bound established with real, verified crypto -- not as a
production latency estimate. That distinction matters enough to the
paper's cost-model claim that it should be stated in the evaluation
section, not just in this docstring.
"""
import os

from _bootstrap import RESULTS_DIR

from sealed_dispatch_eval.metrics import write_csv
from sealed_dispatch_eval.threshold_bls import (
    benchmark_parallel_latency_ms,
    benchmark_sequential_latency_ms,
    self_test,
)

COMMITTEE_K_SWEEP = [1, 3, 5, 7, 11]
COMMITTEE_M = 15
N_TRIALS = 500  # cheap enough now (fast backend) to afford a much cleaner fit


def fit_linear(points):
    """Least-squares fit of latency_ms = base_ms + per_share_ms * k."""
    n = len(points)
    sum_k = sum(k for k, _ in points)
    sum_ms = sum(ms for _, ms in points)
    sum_k2 = sum(k * k for k, _ in points)
    sum_kms = sum(k * ms for k, ms in points)
    denom = n * sum_k2 - sum_k * sum_k
    per_share_ms = (n * sum_kms - sum_k * sum_ms) / denom
    base_ms = (sum_ms - per_share_ms * sum_k) / n
    return base_ms, per_share_ms


def main():
    ok = self_test()
    print(f"threshold BLS self-test: {'PASS' if ok else 'FAIL'}")
    if not ok:
        raise RuntimeError("threshold_bls.self_test() failed -- do not trust benchmark numbers below")

    rows = []
    sequential_points = []
    parallel_points = []
    for k in COMMITTEE_K_SWEEP:
        seq_ms = benchmark_sequential_latency_ms(k, COMMITTEE_M, n_trials=N_TRIALS)
        par_ms = benchmark_parallel_latency_ms(k, COMMITTEE_M, n_trials=N_TRIALS)
        sequential_points.append((k, seq_ms))
        parallel_points.append((k, par_ms))
        old_model_ms = 5.0 + 1.5 * k  # crypto_stub.py's original, unmeasured constants
        rows.append({
            "k_committee": k, "m_committee": COMMITTEE_M,
            "sequential_upper_bound_ms": round(seq_ms, 2),
            "parallel_realistic_estimate_ms": round(par_ms, 2),
            "old_placeholder_model_ms": round(old_model_ms, 2),
            "parallel_over_placeholder_ratio": round(par_ms / old_model_ms, 1),
        })
        print(f"k={k:>2}  sequential(upper bound)={seq_ms:>9.2f}ms  "
              f"parallel(realistic)={par_ms:>8.2f}ms  "
              f"old_placeholder={old_model_ms:>6.2f}ms  "
              f"ratio(parallel/placeholder)={par_ms / old_model_ms:>6.1f}x")

    base_seq, per_share_seq = fit_linear(sequential_points)
    base_par, per_share_par = fit_linear(parallel_points)
    # Latency can't be negative -- a negative fitted intercept at these
    # small (sub-2ms) magnitudes is measurement noise near the origin,
    # not a real effect. Clamp rather than report a physically
    # impossible number.
    base_seq, base_par = max(base_seq, 0.0), max(base_par, 0.0)
    print(f"\nfitted SEQUENTIAL (upper bound) model:  base_ms={base_seq:.2f}  per_share_ms={per_share_seq:.2f}")
    print(f"fitted PARALLEL (realistic) model:       base_ms={base_par:.2f}  per_share_ms={per_share_par:.2f}")
    print("compare to old, unmeasured placeholder:  base_ms=5.0  per_share_ms=1.5")
    print(
        "\nUpdate sealed_dispatch_eval/crypto_stub.py's "
        "threshold_decrypt_latency_ms defaults to these fitted values if "
        "this run's numbers are to be trusted over the previous ones."
    )

    write_csv(os.path.join(RESULTS_DIR, "exp7_real_threshold_bls_benchmark.csv"), rows)


if __name__ == "__main__":
    main()
