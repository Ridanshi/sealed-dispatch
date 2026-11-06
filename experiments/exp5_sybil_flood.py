"""THREAT-MODEL.md §6 item 7 / §4.1 core claim: expected sampled-slot
share for an adversary depends on their *stake share*, not their
*identity count*, under stake-weighted VRF sampling -- and does NOT hold
that property under naive uniform-by-identity sampling.

Three sub-experiments, matching §4.1 point-by-point:
  (a) fix total adversary stake, sweep identity count k
  (b) fix identity count, sweep total adversary stake
  (c) cold-start: sweep number of new (diluted free-tier) registrants
"""
import os

from _bootstrap import RESULTS_DIR

from sealed_dispatch_eval.attackers import SybilFloodAttacker, free_tier_weight
from sealed_dispatch_eval.crypto_stub import commit_hash
from sealed_dispatch_eval.entities import Provider, new_provider_id
from sealed_dispatch_eval.metrics import write_csv
from sealed_dispatch_eval.pool import build_legit_pool
from sealed_dispatch_eval.registry import sample_candidate_set

N_LEGIT = 20
M_CANDIDATE_SET = 5
N_TRIALS = 2000  # independent tasks to average slot-share over


def empirical_slot_share(legit, adversary_providers, mode, m=M_CANDIDATE_SET, n_trials=N_TRIALS):
    adv_ids = {p.provider_id for p in adversary_providers}
    pool = legit + adversary_providers
    total_slots = 0
    adv_slots = 0
    for t in range(n_trials):
        commit = commit_hash(f"task-{t}", "epoch-0")
        nonce = f"nonce-{t}"
        chosen = sample_candidate_set(pool, m, mode, commit, nonce)
        total_slots += len(chosen)
        adv_slots += sum(1 for p in chosen if p.provider_id in adv_ids)
    return adv_slots / total_slots if total_slots else 0.0


def sub_a_sweep_identity_count():
    """(a): fixed total adversary stake, vary k -- should be flat under
    stake_weighted, growing under uniform_by_identity."""
    legit = build_legit_pool(N_LEGIT, seed=1)
    total_legit_stake = sum(p.stake for p in legit)
    s_adv = total_legit_stake * 0.5  # adversary controls 1/3 of total pool stake

    rows = []
    for k in [1, 2, 5, 10, 50, 200, 1000]:
        sybil = SybilFloodAttacker(total_stake=s_adv, num_identities=k)
        adv = sybil.spawn_identities()
        S = total_legit_stake + s_adv
        theoretical_share = s_adv / S  # expected per-slot share under stake-weighted sampling
        for mode in ("stake_weighted", "uniform_by_identity"):
            share = empirical_slot_share(legit, adv, mode)
            rows.append({
                "sub_experiment": "a_identity_count_sweep",
                "sampling_mode": mode,
                "k_identities": k,
                "s_adv": round(s_adv, 2),
                "empirical_slot_share": round(share, 4),
                "theoretical_share_stake_weighted": round(theoretical_share, 4),
            })
            print(f"[a] mode={mode:<20} k={k:>5}  share={share:.4f}  "
                  f"(theory if stake_weighted={theoretical_share:.4f})")
    return rows


def sub_b_sweep_stake():
    """(b): fixed identity count (large, i.e. a flood), vary total stake --
    share should scale ~linearly with s_adv/S under stake_weighted."""
    legit = build_legit_pool(N_LEGIT, seed=1)
    total_legit_stake = sum(p.stake for p in legit)

    rows = []
    for frac in [0.05, 0.1, 0.25, 0.5, 1.0, 2.0]:
        s_adv = total_legit_stake * frac
        sybil = SybilFloodAttacker(total_stake=s_adv, num_identities=100)
        adv = sybil.spawn_identities()
        S = total_legit_stake + s_adv
        theoretical_share = s_adv / S
        for mode in ("stake_weighted", "uniform_by_identity"):
            share = empirical_slot_share(legit, adv, mode)
            rows.append({
                "sub_experiment": "b_stake_sweep",
                "sampling_mode": mode,
                "s_adv_frac_of_legit": frac,
                "s_adv": round(s_adv, 2),
                "empirical_slot_share": round(share, 4),
                "theoretical_share_stake_weighted": round(theoretical_share, 4),
            })
            print(f"[b] mode={mode:<20} s_adv/legit={frac:>5.2f}  share={share:.4f}  "
                  f"(theory if stake_weighted={theoretical_share:.4f})")
    return rows


def sub_c_cold_start():
    """(c): W0_max free-tier pool capped and diluted across new
    registrants -- damage should stay bounded at W0_max/S regardless of
    how many zero-stake identities show up."""
    legit = build_legit_pool(N_LEGIT, seed=1)
    total_legit_stake = sum(p.stake for p in legit)
    w0_max_pool = total_legit_stake * 0.05  # free tier capped at 5% of legit stake

    rows = []
    for new_count in [1, 5, 20, 100, 1000]:
        w0 = free_tier_weight(w0_max_pool, new_count)
        adv = [
            Provider(provider_id=new_provider_id(), stake=w0, true_price=50.0,
                     true_quality=0.5, true_latency_ms=100.0, lie_strength=0.9)
            for _ in range(new_count)
        ]
        S = total_legit_stake + w0_max_pool  # total free-tier weight is capped, not per-identity
        theoretical_bound = w0_max_pool / S
        share = empirical_slot_share(legit, adv, "stake_weighted")
        rows.append({
            "sub_experiment": "c_cold_start",
            "sampling_mode": "stake_weighted",
            "new_registrants": new_count,
            "w0_per_identity": round(w0, 6),
            "empirical_slot_share": round(share, 4),
            "theoretical_bound": round(theoretical_bound, 4),
        })
        print(f"[c] new_registrants={new_count:>5}  w0_each={w0:.6f}  share={share:.4f}  "
              f"(bound={theoretical_bound:.4f})")
    return rows


def main():
    rows = sub_a_sweep_identity_count() + sub_b_sweep_stake() + sub_c_cold_start()
    write_csv(os.path.join(RESULTS_DIR, "exp5_sybil_flood.csv"), rows,
              fieldnames=["sub_experiment", "sampling_mode", "k_identities", "s_adv",
                          "empirical_slot_share", "theoretical_share_stake_weighted",
                          "s_adv_frac_of_legit", "new_registrants", "w0_per_identity",
                          "theoretical_bound"])


if __name__ == "__main__":
    main()
