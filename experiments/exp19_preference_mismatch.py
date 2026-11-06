"""Route-Jacking when the attacker does not know the agent's preferences.

The attacker tunes listings to the harness's default scoring weights (price 0.4, quality 0.4, latency 0.2).
The agent actually scores with different weights. Rows: a few named agents, and random agents drawn from a
Dirichlet around the default (concentration 20 = mild, 5 = strong disagreement). The agent here is still a
weighted-sum scorer, a stand-in for heterogeneous agent preferences, not a language model.
Bazaar-calibrated pool of 50 providers, plaintext dispatch, exact-query attacker, 20 seeds.
"""
import os
import random
from concurrent.futures import ProcessPoolExecutor

from _bootstrap import RESULTS_DIR

from sealed_dispatch_eval.metrics import mean_ci, write_csv
from sealed_dispatch_eval.runner import RunConfig, run

SEEDS = list(range(20))
NAMED = {"default (0.4/0.4/0.2)": None, "price-heavy (0.7/0.2/0.1)": (0.7, 0.2, 0.1),
         "quality-heavy (0.1/0.8/0.1)": (0.1, 0.8, 0.1), "latency-heavy (0.2/0.2/0.6)": (0.2, 0.2, 0.6)}


def one(cfg):
    return run(cfg)


def dirichlet(rng, conc):
    base = (0.4, 0.4, 0.2)
    g = [rng.gammavariate(conc * b, 1.0) for b in base]
    t = sum(g)
    return tuple(x / t for x in g)


def main():
    rows = []
    with ProcessPoolExecutor() as ex:
        for attacker in ("bucket_max", "regression"):
            specs = [(name, [w] * len(SEEDS)) for name, w in NAMED.items()]
            for conc in (20, 5):
                rng = random.Random(conc)
                specs.append((f"random Dirichlet (concentration {conc})",
                              [dirichlet(rng, conc) for _ in SEEDS]))
            for name, ws in specs:
                runs = list(ex.map(one, [RunConfig(n_legit=50, attacker=attacker, view="full", seed=s,
                                                   agent_weights=ws[i]) for i, s in enumerate(SEEDS)],
                                   chunksize=2))
                w = mean_ci([r["win_rate"] for r in runs])
                rv = mean_ci([r["revenue"] for r in runs])
                rows.append({"attacker": attacker, "agent": name, "win_rate": round(w[0], 4),
                             "win_rate_ci95": round(w[1], 4), "revenue_per_task": round(rv[0], 2),
                             "revenue_ci95": round(rv[1], 2)})
                print(rows[-1], flush=True)
    write_csv(os.path.join(RESULTS_DIR, "exp19_preference_mismatch.csv"), rows)


if __name__ == "__main__":
    main()
