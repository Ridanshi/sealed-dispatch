"""Route-Jacking against a plaintext registry and against Sealed Dispatch (blind candidacy plus a
stake-weighted candidate set of 5), at the most predictable setting that keeps two categories.

Eight synthetic providers, bucket-maximum attacker, 500 tasks, 20 seeds. The no-information reference is 1/9.
"""
import os
from concurrent.futures import ProcessPoolExecutor

from _bootstrap import RESULTS_DIR

from sealed_dispatch_eval.metrics import mean_ci, write_csv
from sealed_dispatch_eval.runner import RunConfig, run

SEEDS = list(range(20))


def one(cfg):
    return run(cfg)


def main():
    rows = []
    with ProcessPoolExecutor() as ex:
        for mode, kw in (("plaintext_baseline", dict(selection="all_scored", view="full")),
                         ("sealed_dispatch", dict(selection="stake_m", view="coarse", m=5))):
            runs = list(ex.map(one, [RunConfig(pool="synthetic", n_legit=8, attacker="bucket_max", n_cat=2,
                                               seed=s, **kw) for s in SEEDS]))
            w, wc = mean_ci([r["win_rate"] for r in runs])
            rows.append({"mode": mode, "adversary_win_rate": round(w, 4), "win_rate_ci95": round(wc, 4),
                         "seeds": len(SEEDS)})
    rows.append({"mode": "no_info_reference", "adversary_win_rate": round(1 / 9, 4), "win_rate_ci95": 0.0,
                 "seeds": 0})
    for r in rows:
        print(r)
    write_csv(os.path.join(RESULTS_DIR, "exp2_sealed_dispatch_defense.csv"), rows)


if __name__ == "__main__":
    main()
