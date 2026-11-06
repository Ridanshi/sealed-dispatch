"""Scale, sensitivity and adaptive attackers for Route-Jacking (single honest listing, no Sybils).

(a) Pool size 8 to 200, two provider pools (synthetic, and one whose prices are resampled from real x402
    Bazaar listings), three attackers (bucket maximum, per-category regression, feedback-adaptive margin),
    two attacker views (exact query, coarse view), two selection modes (score every provider, or a
    stake-weighted bounded candidate set with m = 5). 20 seeds per cell, 95% confidence half-widths.
(b) Sensitivity of the Sealed Dispatch configuration to candidate-set size m and to query predictability
    (number of task categories), on the Bazaar-calibrated pool with 50 providers.

Metrics: win rate, price per win, revenue per task (win rate x price per win, the quantity a front-runner
extracts). All runs use the corrected scoring model: price is normalized by the task's own ceiling.
"""
import os
from concurrent.futures import ProcessPoolExecutor

from _bootstrap import RESULTS_DIR

from sealed_dispatch_eval.metrics import mean_ci, write_csv
from sealed_dispatch_eval.runner import RunConfig, run

SEEDS = list(range(20))
ATTACKERS = ("bucket_max", "regression", "feedback")


def one(cfg):
    return run(cfg)


def cell(ex, **kw):
    runs = list(ex.map(one, [RunConfig(seed=s, **kw) for s in SEEDS], chunksize=2))
    w, wc = mean_ci([r["win_rate"] for r in runs])
    p, _ = mean_ci([r["price_per_win"] for r in runs])
    rv, rc = mean_ci([r["revenue"] for r in runs])
    rg, rgc = mean_ci([r["regret"] for r in runs])
    return {"win_rate": round(w, 4), "win_rate_ci95": round(wc, 4), "price_per_win": round(p, 2),
            "revenue_per_task": round(rv, 2), "revenue_ci95": round(rc, 2),
            "agent_regret": round(rg, 4), "agent_regret_ci95": round(rgc, 4)}


def main():
    rows_a, rows_b = [], []
    with ProcessPoolExecutor() as ex:
        for pool in ("synthetic", "bazaar"):
            for n_legit in (8, 20, 50, 100, 200):
                for attacker in ATTACKERS:
                    for selection in ("all_scored", "stake_m"):
                        for view in ("full", "coarse"):
                            r = cell(ex, pool=pool, n_legit=n_legit, attacker=attacker, view=view,
                                     selection=selection)
                            rows_a.append({"pool": pool, "n_legit": n_legit, "attacker": attacker,
                                           "selection": selection, "view": view, "seeds": len(SEEDS), **r})
                            print(rows_a[-1], flush=True)
        for m in (3, 5, 10, 20):
            for view in ("full", "coarse"):
                rows_b.append({"axis": "m", "value": m, "view": view,
                               **cell(ex, n_legit=50, view=view, selection="stake_m", m=m)})
        for n_cat in (1, 2, 4, 8, 16):
            for view in ("full", "coarse"):
                rows_b.append({"axis": "categories", "value": n_cat, "view": view,
                               **cell(ex, n_legit=50, view=view, selection="stake_m", n_cat=n_cat)})
    write_csv(os.path.join(RESULTS_DIR, "exp14a_scale_adaptive.csv"), rows_a)
    write_csv(os.path.join(RESULTS_DIR, "exp14b_sensitivity.csv"), rows_b)


if __name__ == "__main__":
    main()
