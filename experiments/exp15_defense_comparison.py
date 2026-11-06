"""Sealed Dispatch against alternative mitigations of Route-Jacking, under three attackers.

All defenses face the same workload: Bazaar-calibrated pool of 50 providers, two categories, 500 tasks,
20 seeds. For each defense the table reports the *worst case over the three attackers* (bucket maximum,
regression, feedback-adaptive margin) for win rate and for revenue per task, and the agent's regret
(score lost against scoring every provider, worst case over the three attackers), which is the cost side.

  plaintext          score everyone, attacker sees the exact query
  rate_limited       plaintext, but the attacker may observe the legitimate best score on 10% of tasks
  bid_first          sealed-bid style: the attacker sees only the category when it must commit its bid
  lottery_tau        plaintext with a near-tie lottery of width tau (public seed, no beacon)
  bounded_m10        stake-weighted candidate set of 10, coarse attacker view
  sealed_m10_lot     bounded_m10 plus a beacon-seeded near-tie lottery (tau = 0.05)
  sealed_m20         stake-weighted candidate set of 20, coarse attacker view
"""
import os
from concurrent.futures import ProcessPoolExecutor

from _bootstrap import RESULTS_DIR

from sealed_dispatch_eval.metrics import mean_ci, write_csv
from sealed_dispatch_eval.runner import RunConfig, run

SEEDS = list(range(20))
ATTACKERS = ("bucket_max", "regression", "feedback")
DEFENSES = {
    "plaintext": dict(selection="all_scored", view="full"),
    "rate_limited": dict(selection="all_scored", view="full", recon_rate=0.1),
    "bid_first": dict(selection="all_scored", view="category"),
    "lottery_tau0.02": dict(selection="all_scored", view="full", tau=0.02),
    "lottery_tau0.05": dict(selection="all_scored", view="full", tau=0.05),
    "lottery_tau0.10": dict(selection="all_scored", view="full", tau=0.10),
    "bounded_m10": dict(selection="stake_m", view="coarse", m=10),
    "sealed_m10_lot": dict(selection="stake_m", view="coarse", m=10, tau=0.05),
    "sealed_m20": dict(selection="stake_m", view="coarse", m=20),
}


def one(cfg):
    return run(cfg)


def main():
    rows, summary = [], []
    with ProcessPoolExecutor() as ex:
        for name, kw in DEFENSES.items():
            per_att = {}
            for att in ATTACKERS:
                runs = list(ex.map(one, [RunConfig(n_legit=50, attacker=att, seed=s, **kw) for s in SEEDS],
                                   chunksize=2))
                w = mean_ci([r["win_rate"] for r in runs])
                rv = mean_ci([r["revenue"] for r in runs])
                rg = mean_ci([r["regret"] for r in runs])
                per_att[att] = (w, rv, rg)
                rows.append({"defense": name, "attacker": att, "win_rate": round(w[0], 4),
                             "win_rate_ci95": round(w[1], 4), "revenue_per_task": round(rv[0], 2),
                             "revenue_ci95": round(rv[1], 2), "agent_regret": round(rg[0], 4)})
            worst_w = max(per_att.values(), key=lambda t: t[0][0])
            worst_r = max(per_att.values(), key=lambda t: t[1][0])
            summary.append({"defense": name, "worst_win_rate": round(worst_w[0][0], 4),
                            "worst_win_rate_ci95": round(worst_w[0][1], 4),
                            "worst_revenue_per_task": round(worst_r[1][0], 2),
                            "worst_revenue_ci95": round(worst_r[1][1], 2),
                            # regret is also the worst case over the attackers: the lottery's regret is lowest against an attacker
                            # that overbids (it pays the margin), so taking it from the worst-win attacker understated it
                            "agent_regret": round(max(v[2][0] for v in per_att.values()), 4)})
            print(summary[-1], flush=True)
    write_csv(os.path.join(RESULTS_DIR, "exp15_defense_comparison_by_attacker.csv"), rows)
    write_csv(os.path.join(RESULTS_DIR, "exp15_defense_comparison.csv"), summary)


if __name__ == "__main__":
    main()
