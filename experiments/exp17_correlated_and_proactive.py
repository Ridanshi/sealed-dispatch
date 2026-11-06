"""Committee dependability beyond independent crashes.

(a) Correlated failures. Members live in failure domains (a cloud region, an operator). A domain is down
    with probability r, and each member is additionally offline with probability q = 0.05. Liveness of a
    (k, n) = (5, 9) committee under three placements: all nine in one domain, three domains of three, nine
    domains of one. 200,000 Monte Carlo trials each.
(b) Adaptive corruption with and without proactive share refresh. An adversary corrupts each honest member
    independently with probability rho per epoch; corrupted members stay corrupted until the next refresh,
    which re-randomizes every share (threshold_bls.refresh) and evicts the adversary. The beacon is
    compromised in any epoch where at least k members are corrupted. Horizon 1000 epochs, 4000 trials.
(c) A real-crypto check of refresh: shares from different epochs do not combine.
"""
import os
import random

from _bootstrap import RESULTS_DIR

from sealed_dispatch_eval.metrics import write_csv
import py_arkworks_bls12381 as ark

from sealed_dispatch_eval.threshold_bls import DST_MESSAGE, ThresholdBLSCommittee, _G1_BASIS

SEED = 20260202


def correlated_rows():
    rng = random.Random(SEED)
    k, n, q, trials = 5, 9, 0.05, 200_000
    placements = {"one_domain": 1, "three_domains": 3, "nine_domains": 9}
    rows = []
    for r in (0.01, 0.05, 0.10):
        for name, n_dom in placements.items():
            size = n // n_dom
            ok = 0
            for _ in range(trials):
                online = 0
                for _d in range(n_dom):
                    if rng.random() < r:
                        continue
                    online += sum(1 for _ in range(size) if rng.random() >= q)
                ok += online >= k
            rows.append({"k": k, "n": n, "p_domain_down": r, "p_member_offline": q, "placement": name,
                         "p_live": round(ok / trials, 5), "trials": trials})
            print(rows[-1], flush=True)
    return rows


def proactive_rows():
    rng = random.Random(SEED + 1)
    horizon, trials = 1000, 4000
    rows = []
    for k, n in ((3, 5), (6, 11)):
        for rho in (0.001, 0.005, 0.01):
            for T in (None, 100, 25, 5, 1):
                bad = 0
                for _ in range(trials):
                    corrupt = [False] * n
                    for epoch in range(1, horizon + 1):
                        if T is not None and epoch % T == 0:
                            corrupt = [False] * n
                        for i in range(n):
                            if not corrupt[i] and rng.random() < rho:
                                corrupt[i] = True
                        if sum(corrupt) >= k:
                            bad += 1
                            break
                rows.append({"k": k, "n": n, "rho_per_epoch": rho,
                             "refresh_every_epochs": "never" if T is None else T,
                             "horizon_epochs": horizon, "p_beacon_compromised": round(bad / trials, 4),
                             "trials": trials})
                print(rows[-1], flush=True)
    return rows


def refresh_check():
    c = ThresholdBLSCommittee(3, 5)
    msg = b"refresh-check"
    pk_before = c.pk
    old = {i: c.partial_sign(i, msg) for i in (1, 2, 3)}
    c.refresh()
    new = {i: c.partial_sign(i, msg) for i in (1, 2, 3)}
    mixed = {1: old[1], 2: old[2], 3: new[3]}
    sig_new = c.combine(new)
    M = ark.G2Point.hash_to_curve(msg, DST_MESSAGE)
    row = {"new_shares_verify": c.verify(msg, sig_new),
           # verified against the public key captured *before* the refresh, not the committee's current field
           "verifies_under_pre_refresh_public_key": bool(ark.GT.pairing_check(
               [_G1_BASIS, -pk_before], [ark.G2Point.from_compressed_bytes(sig_new), M])),
           "two_old_plus_one_new_verify": c.verify(msg, c.combine(mixed)),
           "three_old_verify": c.verify(msg, c.combine(old))}
    print(row)
    return [row]


def main():
    write_csv(os.path.join(RESULTS_DIR, "exp17a_correlated_failures.csv"), correlated_rows())
    write_csv(os.path.join(RESULTS_DIR, "exp17b_proactive_refresh.csv"), proactive_rows())
    write_csv(os.path.join(RESULTS_DIR, "exp17c_refresh_crypto_check.csv"), refresh_check())


if __name__ == "__main__":
    main()
