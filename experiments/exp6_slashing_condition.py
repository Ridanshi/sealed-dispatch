"""Bonus, tied directly to THREAT-MODEL.md §4.1 step 6: numerically check
the slashing viability condition

    p_detect * gamma * stake > (1 - p_detect) * fraudulent_gain

by (1) evaluating the closed-form EV analytically across a parameter
sweep, and (2) confirming a Monte Carlo simulation of the underlying
either/or lottery agrees with the analytic sign in expectation.

This experiment is also what caught the first (wrong) version of this
formula: an earlier draft used `fraudulent_gain - gamma*stake*p_detect`,
which keeps the gain unconditionally instead of weighting it by
(1 - p_detect). The two disagreed in sign on real parameter combinations
-- see sealed_dispatch_eval/attackers.py:slashing_expected_value for the
corrected derivation.
"""
import os
import random

from _bootstrap import RESULTS_DIR

from sealed_dispatch_eval.attackers import slashing_expected_value
from sealed_dispatch_eval.metrics import mean_std, write_csv

N_TRIALS = 20000


def monte_carlo_ev_of_lying(stake: float, gamma: float, p_detect: float,
                             fraudulent_gain: float, n_trials: int = N_TRIALS, seed: int = 0):
    rng = random.Random(seed)
    payoffs = []
    for _ in range(n_trials):
        if rng.random() < p_detect:
            payoffs.append(-gamma * stake)  # caught: slashed, no gain kept
        else:
            payoffs.append(fraudulent_gain)  # not caught: keeps the gain
    return mean_std(payoffs)


def main():
    rows = []
    stake = 100.0
    for gamma in [0.1, 0.3, 0.5, 0.8, 1.0]:
        for p_detect in [0.05, 0.1, 0.3, 0.5, 0.8]:
            for fraudulent_gain in [2.0, 5.0, 10.0, 20.0, 50.0]:
                analytic_ev = slashing_expected_value(stake, gamma, p_detect, fraudulent_gain)
                mc_mean, mc_std = monte_carlo_ev_of_lying(stake, gamma, p_detect, fraudulent_gain)
                deters = analytic_ev < 0
                agree = (analytic_ev < 0) == (mc_mean < 0)
                rows.append({
                    "stake": stake, "gamma": gamma, "p_detect": p_detect,
                    "fraudulent_gain": fraudulent_gain,
                    "analytic_ev_of_lying": round(analytic_ev, 3),
                    "monte_carlo_ev_of_lying": round(mc_mean, 3),
                    "monte_carlo_std": round(mc_std, 3),
                    "slashing_deters_lying": deters,
                    "analytic_mc_agree": agree,
                })

    n_disagree = sum(1 for r in rows if not r["analytic_mc_agree"])
    print(f"{len(rows)} parameter combos checked, {n_disagree} analytic/Monte-Carlo sign disagreements")
    write_csv(os.path.join(RESULTS_DIR, "exp6_slashing_condition.csv"), rows)


if __name__ == "__main__":
    main()
