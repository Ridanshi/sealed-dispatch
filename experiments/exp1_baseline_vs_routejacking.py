"""Route-Jacking on a plaintext registry as a function of query predictability.

One honest listing per task, bucket-maximum attacker with the exact query, eight synthetic providers, 500
tasks, 20 seeds. Fewer categories means more reuse, so the attacker's per-bucket estimate converges faster.
"""
import os
from concurrent.futures import ProcessPoolExecutor

from _bootstrap import RESULTS_DIR

from sealed_dispatch_eval.metrics import mean_ci, write_csv
from sealed_dispatch_eval.runner import RunConfig, run

CATEGORY_SWEEP = [1, 2, 4, 8, 16, 32]
SEEDS = list(range(20))


def one(cfg):
    return run(cfg)


def main():
    rows = []
    with ProcessPoolExecutor() as ex:
        for nc in CATEGORY_SWEEP:
            runs = list(ex.map(one, [RunConfig(pool="synthetic", n_legit=8, attacker="bucket_max", view="full",
                                               selection="all_scored", n_cat=nc, seed=s) for s in SEEDS]))
            w, wc = mean_ci([r["win_rate"] for r in runs])
            rows.append({"num_categories": nc, "n_tasks": 500, "n_legit": 8, "seeds": len(SEEDS),
                         "adversary_win_rate": round(w, 4), "win_rate_ci95": round(wc, 4),
                         "no_info_baseline": round(1.0 / 9, 4)})
            print(rows[-1])
    write_csv(os.path.join(RESULTS_DIR, "exp1_baseline_vs_routejacking.csv"), rows)


if __name__ == "__main__":
    main()
