# -*- coding: utf-8 -*-
"""Property tests: the paper's statements, checked against the implementation (run: python tests/test_properties.py)."""
import itertools
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sealed_dispatch_eval.crypto_stub import commit_hash
from sealed_dispatch_eval.dispatch import dispatch_baseline, dispatch_sealed
from sealed_dispatch_eval.entities import Provider, TaskQuery, new_provider_id
from sealed_dispatch_eval.policy import score, select_winner, select_winner_lottery
from sealed_dispatch_eval.pool import build_legit_pool, task_stream
from sealed_dispatch_eval.registry import sample_candidate_set
from sealed_dispatch_eval.runner import RunConfig, run
from sealed_dispatch_eval.threshold_bls import ThresholdBLSCommittee

failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  ({detail})" if detail else ""))
    if not cond:
        failures.append(name)


def rand_bids(rng, n):
    return [(i, rng.uniform(5, 90), rng.uniform(0.3, 1.0), rng.uniform(20, 900)) for i in range(n)]


# ---- Proposition 4: regret <= tau; win probability <= 1/2 within tau; certain beyond tau
rng = random.Random(1)
ok_regret, worst = True, 0.0
for _ in range(3000):
    bids = rand_bids(rng, rng.randint(2, 12)); ceil = rng.uniform(40, 100); tau = rng.choice([0.0, 0.02, 0.05, 0.1])
    wid, ws = select_winner_lottery(bids, ceil, tau, rng.getrandbits(40))
    best = max(score(p, q, l, ceil) for _, p, q, l in bids)
    worst = max(worst, best - ws)
    ok_regret &= best - ws <= tau + 1e-12
check("Prop 4: lottery regret <= tau on 3000 random draws", ok_regret, f"max regret {worst:.4f}")

legit = [(i, 50.0, 0.8, 200.0) for i in range(3)]
ceil = 70.0
best_legit = max(score(p, q, l, ceil) for _, p, q, l in legit)
tau = 0.05


def attacker_with_margin(m):
    # find a price whose score is best_legit + m
    lo, hi = 0.01, 70.0
    for _ in range(60):
        mid = (lo + hi) / 2
        s = score(mid, 0.95, 50.0, ceil)
        lo, hi = (mid, hi) if s > best_legit + m else (lo, mid)
    return (99, (lo + hi) / 2, 0.95, 50.0)


for margin, expect in ((0.02, "<=1/2"), (0.04, "<=1/2"), (0.06, "certain")):
    a = attacker_with_margin(margin)
    wins = sum(select_winner_lottery(legit + [a], ceil, tau, s * 7919 + 13)[0] == 99 for s in range(4000))
    freq = wins / 4000
    if expect == "<=1/2":
        check(f"Prop 4: margin {margin} <= tau wins at most 1/2", freq <= 0.5 + 0.03, f"freq {freq:.3f}")
    else:
        check(f"Prop 4: margin {margin} > tau wins with certainty", freq == 1.0, f"freq {freq:.3f}")

# ---- Theorem 1: without-replacement cap and first-draw proportionality
pool = build_legit_pool(20, seed=3)
adv = [Provider(new_provider_id(), stake=40.0, true_price=50, true_quality=0.5, true_latency_ms=100) for _ in range(7)]
mx = 0
for t in range(1500):
    ch = sample_candidate_set(pool + adv, 5, "stake_weighted", commit_hash(f"t{t}", "e"), f"n{t}")
    ids = [p.provider_id for p in ch]
    mx = max(mx, sum(p.provider_id in {a.provider_id for a in adv} for p in ch))
    assert len(ids) == len(set(ids)), "duplicate candidate"
check("Theorem 1(b): no identity drawn twice; adversary slots <= min(m, k)", mx <= 5, f"max adversary slots {mx}")
one = pool[:1] + []
first = {p.provider_id: 0 for p in pool}
for t in range(20000):
    ch = sample_candidate_set(pool, 1, "stake_weighted", commit_hash(f"x{t}", "e"), f"y{t}")
    first[ch[0].provider_id] += 1
S = sum(p.stake for p in pool)
dev = max(abs(first[p.provider_id] / 20000 - p.stake / S) for p in pool)
check("Theorem 1: first draw probability proportional to stake", dev < 0.012, f"max deviation {dev:.4f}")

# ---- the commitment binds the task: same coarse view and epoch, different tasks, different candidate sets
legit8 = build_legit_pool(8, seed=5)
tasks = [TaskQuery(task_id=i, category="c0", price_ceiling=55.0, quality_floor=0.6) for i in range(40)]
sets = {tuple(sorted(p.provider_id for p in sample_candidate_set(
    legit8, 5, "stake_weighted", commit_hash(f"{t.task_id}|{sorted(t.coarse_view().items())}", "epoch-0"), "epoch-0"))) for t in tasks}
check("commitment binds the task: >1 distinct candidate set for identical coarse views", len(sets) > 5, f"{len(sets)} distinct sets")

# ---- regret is zero when everyone is scored and the policy is deterministic
r = run(RunConfig(pool="synthetic", n_legit=8, attacker="bucket_max", view="full", selection="all_scored", n_tasks=200, seed=1))
check("regret is 0 for plaintext deterministic dispatch", abs(r["regret"]) < 1e-12, f"regret {r['regret']}")
r2 = run(RunConfig(pool="synthetic", n_legit=8, attacker="bucket_max", view="full", selection="all_scored", n_tasks=200, seed=1))
check("runs are deterministic for a fixed seed", r == r2)

# ---- score uses the task ceiling (the fixed bug): same bid, different ceilings, different scores
check("score depends on the task ceiling", score(40, 0.8, 100, 50.0) != score(40, 0.8, 100, 90.0))

# ---- Theorem 3: naive combiner probability matches C(n-b,k)/C(n,k) on real signatures
from math import comb
c = ThresholdBLSCommittee(3, 5)
import py_arkworks_bls12381 as ark
from sealed_dispatch_eval.threshold_bls import DST_MESSAGE
rng = random.Random(9)
ok_n = 0; N = 120
for t in range(N):
    msg = f"m{t}".encode()
    bad = set(rng.sample(range(1, 6), 1))
    order = list(range(1, 6)); rng.shuffle(order)
    junk = ark.G2Point.hash_to_curve(b"x", DST_MESSAGE) * ark.Scalar(777)
    parts = {i: (junk if i in bad else c.partial_sign(i, msg)) for i in order}
    ok_n += int(c.verify(msg, c.combine(parts)))
freq = ok_n / N
check("Theorem 3(b): naive combiner success ~ C(n-b,k)/C(n,k) = 0.4", abs(freq - comb(4, 3) / comb(5, 3)) < 0.12, f"freq {freq:.2f}")
parts = {i: (junk if i == 1 else c.partial_sign(i, b"z")) for i in range(1, 6)}
sig, rej = c.combine_robust(b"z", parts)
check("Theorem 3(b): robust combiner drops the invalid partial and verifies", c.verify(b"z", sig) and rej == [1])

# ---- Theorem 2 sign: EV formula
EV = lambda Pd, g, gam, s: (1 - Pd) * g - Pd * gam * s
check("Theorem 2: EV sign matches the deterrence condition", all(
    (EV(Pd, g, gam, s) < 0) == (Pd * gam * s > (1 - Pd) * g)
    for Pd, g, gam, s in itertools.product((0.1, 0.5, 0.9), (1, 10, 50), (0.1, 0.5, 1.0), (10, 100))))

print("\n%d failure(s)" % len(failures))
sys.exit(1 if failures else 0)
