"""Committee fault tolerance (liveness and safety) for the Sealed Dispatch beacon.

The Lock phase needs k of n committee members to produce a threshold-BLS
partial signature. This experiment asks what happens when members crash,
return garbage, or collude.

(a) Liveness under crash faults. Each member is independently offline with
    probability q. The beacon is produced iff at least k members respond:
    P_live = P(Binomial(n, 1-q) >= k). Checked three ways: closed form,
    a 20,000-trial availability Monte Carlo, and a real-crypto run in which
    online members actually sign and the aggregator actually combines and
    verifies the result.
(b) Byzantine partials. b members return a well-formed but invalid partial.
    The naive combiner (first k responses, no checks) vs the robust combiner
    (verify each partial against the member's public key, drop failures).
(c) Safety vs liveness as k varies. Safety needs fewer than k corrupt members;
    liveness needs at least k honest online members. Closed forms for both
    failure probabilities, plus a real-crypto check that k-1 shares plus a
    forged partial cannot produce a valid signature and that k shares can.
(d) End-to-end degraded dispatch. Route-Jacking attacker as in exp2, with the
    committee failing per task with the probability from (a), under four
    fallback policies, plus a compromised-beacon (grinding) row.
"""
import math
import os
import random
import statistics as stats
import zlib

from _bootstrap import RESULTS_DIR

import py_arkworks_bls12381 as ark

from sealed_dispatch_eval.attackers import RouteJackingAttacker
from sealed_dispatch_eval.dispatch import dispatch_baseline, dispatch_sealed
from sealed_dispatch_eval.metrics import mean_ci, win_rate, write_csv
from sealed_dispatch_eval.policy import select_winner
from sealed_dispatch_eval.pool import build_legit_pool, task_stream
from sealed_dispatch_eval.threshold_bls import ThresholdBLSCommittee

SEED = 20260101
CONFIGS = [(1, 3), (3, 5), (5, 11), (7, 11)]  # (k, n)
Q_SWEEP = [0.0, 0.05, 0.1, 0.2, 0.3, 0.5]
AVAIL_TRIALS = 20000
CRYPTO_TRIALS = 40
BYZ_TRIALS = 150

N_TASKS = 500
N_LEGIT = 8
NUM_CATEGORIES = 2
M_CANDIDATE_SET = 5
K_COMMITTEE, N_COMMITTEE = 3, 5
GRIND_ATTEMPTS = 16
ROUND_TIMEOUT_MS = 100.0
MAX_RETRIES = 2


def binom_tail_ge(n: int, p: float, k: int) -> float:
    """P(Binomial(n, p) >= k)."""
    return sum(math.comb(n, j) * p ** j * (1 - p) ** (n - j) for j in range(k, n + 1))


def liveness_rows():
    rng = random.Random(SEED)
    rows = []
    for k, n in CONFIGS:
        committee = ThresholdBLSCommittee(k=k, n=n)
        for q in Q_SWEEP:
            analytic = binom_tail_ge(n, 1 - q, k)
            mc_ok = sum(
                sum(1 for _ in range(n) if rng.random() >= q) >= k for _ in range(AVAIL_TRIALS)
            )
            agree = 0
            for t in range(CRYPTO_TRIALS):
                msg = f"liveness-{k}-{n}-{q}-{t}".encode()
                online = [i for i in range(1, n + 1) if rng.random() >= q]
                partials = {i: committee.partial_sign(i, msg) for i in online}
                try:
                    sig, _ = committee.combine_robust(msg, partials)
                    produced = committee.verify(msg, sig)
                except ValueError:
                    produced = False
                agree += int(produced == (len(online) >= k))
            rows.append({
                "k": k, "n": n, "q_offline": q,
                "p_live_analytic": round(analytic, 5),
                "p_live_montecarlo": round(mc_ok / AVAIL_TRIALS, 5),
                "crypto_trials": CRYPTO_TRIALS,
                "crypto_matches_rule": agree,
            })
            print(f"(a) k={k} n={n:>2} q={q:<4}  analytic={analytic:.4f}  mc={mc_ok / AVAIL_TRIALS:.4f}  "
                  f"real-BLS rule agreement {agree}/{CRYPTO_TRIALS}")
    return rows


def byzantine_rows():
    rng = random.Random(SEED + 1)
    rows = []
    for k, n in [(3, 5), (5, 11)]:
        committee = ThresholdBLSCommittee(k=k, n=n)
        for b in range(0, n - k + 2):
            naive_ok = robust_ok = 0
            for t in range(BYZ_TRIALS):
                msg = f"byz-{k}-{n}-{b}-{t}".encode()
                bad = set(rng.sample(range(1, n + 1), b))
                junk = ark.G2Point.hash_to_curve(b"garbage", b"junk-dst") * ark.Scalar(rng.randrange(1, 10 ** 9))
                order = list(range(1, n + 1))
                rng.shuffle(order)  # arrival order at the aggregator
                partials = {i: (junk if i in bad else committee.partial_sign(i, msg)) for i in order}
                naive_ok += int(committee.verify(msg, committee.combine(partials)))
                try:
                    sig, _ = committee.combine_robust(msg, partials)
                    robust_ok += int(committee.verify(msg, sig))
                except ValueError:
                    pass
            naive_theory = math.comb(n - b, k) / math.comb(n, k)
            rows.append({
                "k": k, "n": n, "b_invalid": b,
                "naive_success": round(naive_ok / BYZ_TRIALS, 4),
                "naive_theory": round(naive_theory, 4),
                "robust_success": round(robust_ok / BYZ_TRIALS, 4),
                "robust_theory": 1.0 if n - b >= k else 0.0,
                "trials": BYZ_TRIALS,
            })
            print(f"(b) k={k} n={n:>2} b={b}  naive={naive_ok / BYZ_TRIALS:.2f} (theory {naive_theory:.2f})  "
                  f"robust={robust_ok / BYZ_TRIALS:.2f}")
    return rows


def safety_rows():
    rows = []
    n = 11
    for p in [0.05, 0.1, 0.2]:
        for k in range(1, n + 1):
            rows.append({
                "n": n, "k": k, "p_fault": p,
                "p_liveness_loss": round(1 - binom_tail_ge(n, 1 - p, k), 6),   # fewer than k members online
                "p_beacon_compromise": round(binom_tail_ge(n, p, k), 6),        # k or more corrupt members
            })
    # Real-crypto safety check: k-1 shares + a forged share cannot sign; k shares can.
    committee = ThresholdBLSCommittee(k=3, n=5)
    msg = b"safety-check"
    forged_ok = 0
    for t in range(CRYPTO_TRIALS):
        known = {i: committee.partial_sign(i, msg) for i in (1, 2)}              # k-1 = 2 colluders
        known[3] = ark.G2Point.hash_to_curve(f"guess-{t}".encode(), b"junk-dst")  # best guess for the 3rd share
        forged_ok += int(committee.verify(msg, committee.combine(known)))
    k_ok = int(committee.verify(msg, committee.combine({i: committee.partial_sign(i, msg) for i in (1, 3, 5)})))
    print(f"(c) real BLS (3,5): k-1 colluders + forged share valid in {forged_ok}/{CRYPTO_TRIALS} trials; "
          f"k colluders reconstruct valid sig: {bool(k_ok)}")
    rows.append({"n": 5, "k": 3, "p_fault": "real_crypto_check",
                 "p_liveness_loss": f"forge_success={forged_ok}/{CRYPTO_TRIALS}",
                 "p_beacon_compromise": f"k_colluders_reconstruct={bool(k_ok)}"})
    return rows


def degraded_dispatch(policy: str, q: float, seed: int = 0):
    """One run of the exp2 Route-Jacking workload with the committee failing per task.

    The attacker records the legitimate best score under both the full and coarse keys on every
    task (market research off the dispatch path, as in exp2), so its knowledge does not depend on
    which path a task took."""
    rng = random.Random(SEED + int(q * 1000) + zlib.crc32(policy.encode()) % 997 + 7919 * seed)
    p_live = binom_tail_ge(N_COMMITTEE, 1 - q, K_COMMITTEE)
    legit = build_legit_pool(N_LEGIT, seed=42 + seed)
    mean_stake = stats.mean(p.stake for p in legit)
    tasks = task_stream(N_TASKS, NUM_CATEGORIES, seed=7 + seed)
    attacker = RouteJackingAttacker(stake=mean_stake)
    won = served = attempts_total = 0
    for task in tasks:
        retries = MAX_RETRIES if policy.startswith("retry") else 0
        committee_ok = False
        attempts = 0
        for _ in range(retries + 1):
            attempts += 1
            if rng.random() < p_live:
                committee_ok = True
                break
        attempts_total += attempts
        nonce = f"s{seed}-{task.task_id // 50}"  # same stream as runner.py, so q = 0 reproduces exp2 exactly
        _, legit_best = select_winner([(p.provider_id, *p.claim()) for p in legit], task.price_ceiling)
        if committee_ok:
            listing = attacker.craft_listing(task, "coarse", task.price_ceiling)
            if policy == "compromised_beacon":
                res = None
                for g in range(GRIND_ATTEMPTS):
                    res = dispatch_sealed(task, legit + [listing], {listing.provider_id}, M_CANDIDATE_SET,
                                          "stake_weighted", K_COMMITTEE, N_COMMITTEE, f"{nonce}-g{g}")
                    if res.adversary_won:
                        break
            else:
                res = dispatch_sealed(task, legit + [listing], {listing.provider_id}, M_CANDIDATE_SET,
                                      "stake_weighted", K_COMMITTEE, N_COMMITTEE, nonce)
            served += 1
            won += int(res.adversary_won)
        elif policy.endswith("fail_open"):
            listing = attacker.craft_listing(task, "full", task.price_ceiling)
            res = dispatch_baseline(task, legit + [listing], {listing.provider_id})
            served += 1
            won += int(res.adversary_won)
        # fail_closed: task is not dispatched
        attacker.observe(task, "full", legit_best)
        attacker.observe(task, "coarse", legit_best)
    return {
        "policy": policy, "q_offline": q, "p_committee_live": round(p_live, 4),
        "availability": round(served / N_TASKS, 4),
        "adv_wins_per_dispatched": round(won / served, 4) if served else 0.0,
        "adv_wins_per_submitted": round(won / N_TASKS, 4),
        "mean_extra_latency_ms": round(ROUND_TIMEOUT_MS * (attempts_total / N_TASKS - 1), 2),
    }


DEGRADED_SEEDS = list(range(20))


def degraded_rows():
    rows = []
    cases = [(pol, q) for q in (0.0, 0.1, 0.2, 0.4, 0.6)
             for pol in ("fail_closed", "fail_open", "retry_fail_closed", "retry_fail_open")]
    cases.append(("compromised_beacon", 0.0))
    for pol, q in cases:
        runs = [degraded_dispatch(pol, q, s) for s in DEGRADED_SEEDS]
        avail = mean_ci([r["availability"] for r in runs])
        win = mean_ci([r["adv_wins_per_dispatched"] for r in runs])
        row = {"policy": pol, "q_offline": q, "p_committee_live": runs[0]["p_committee_live"],
               "availability": round(avail[0], 4), "adv_wins_per_dispatched": round(win[0], 4),
               "adv_wins_ci95": round(win[1], 4),
               "mean_extra_latency_ms": round(sum(r["mean_extra_latency_ms"] for r in runs) / len(runs), 2),
               "seeds": len(DEGRADED_SEEDS)}
        rows.append(row)
        print("(d)", row, flush=True)
    return rows


def main():
    write_csv(os.path.join(RESULTS_DIR, "exp9a_liveness.csv"), liveness_rows())
    write_csv(os.path.join(RESULTS_DIR, "exp9b_byzantine_partials.csv"), byzantine_rows())
    write_csv(os.path.join(RESULTS_DIR, "exp9c_safety_liveness_tradeoff.csv"), safety_rows())
    write_csv(os.path.join(RESULTS_DIR, "exp9d_degraded_dispatch.csv"), degraded_rows())


if __name__ == "__main__":
    main()
