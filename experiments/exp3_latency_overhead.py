"""THREAT-MODEL.md §6 item 5: latency overhead of Sealed Dispatch vs the
plaintext baseline, in absolute ms and as a % of end-to-end task latency
(dominated in practice by LLM inference, assumed here at a representative
value -- see LLM_INFERENCE_MS -- so the "small tax relative to inference"
argument from §4's cost model gets a concrete number, not just a claim).
"""
import os

from _bootstrap import RESULTS_DIR

from sealed_dispatch_eval.crypto_stub import threshold_decrypt_latency_ms
from sealed_dispatch_eval.metrics import write_csv

BASE_LATENCY_MS = 20.0
LLM_INFERENCE_MS = 800.0  # representative single-turn tool-call latency
COMMITTEE_K_SWEEP = [1, 3, 5, 7, 11]
COMMITTEE_M = 15
CANDIDACY_WINDOW_SWEEP_MS = [10.0, 30.0, 60.0, 120.0]


def main():
    rows = []
    for k in COMMITTEE_K_SWEEP:
        for window_ms in CANDIDACY_WINDOW_SWEEP_MS:
            decrypt_ms = threshold_decrypt_latency_ms(k, COMMITTEE_M)
            sealed_latency = BASE_LATENCY_MS + window_ms + decrypt_ms
            overhead_ms = sealed_latency - BASE_LATENCY_MS
            e2e = LLM_INFERENCE_MS + sealed_latency
            overhead_pct_of_e2e = 100.0 * overhead_ms / e2e
            rows.append({
                "k_committee": k,
                "m_committee": COMMITTEE_M,
                "candidacy_window_ms": window_ms,
                "baseline_latency_ms": BASE_LATENCY_MS,
                "sealed_latency_ms": round(sealed_latency, 2),
                "overhead_ms": round(overhead_ms, 2),
                "overhead_pct_of_e2e": round(overhead_pct_of_e2e, 2),
            })

    for r in rows:
        print(f"k={r['k_committee']:>2} window={r['candidacy_window_ms']:>6.0f}ms  "
              f"overhead={r['overhead_ms']:>7.2f}ms  ({r['overhead_pct_of_e2e']:.2f}% of e2e)")

    write_csv(os.path.join(RESULTS_DIR, "exp3_latency_overhead.csv"), rows)


if __name__ == "__main__":
    main()
