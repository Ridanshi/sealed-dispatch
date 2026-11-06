"""THREAT-MODEL.md §6 item 6: sweep committee size (k-of-m) and candidacy
window length; plot the security/latency Pareto frontier.

Security metric: adversary win-rate under a combined attack (one
Route-Jacking listing + a moderate Sybil flood) with Sealed Dispatch +
stake-weighted sampling active. Window length matters here because a
longer candidacy window lets more legitimate providers register before
the set is sampled (modeled via REGISTRATION_RATE_PER_MS) -- more honest
competition dilutes the Sybils, at the direct cost of latency. That's the
actual tradeoff this experiment is meant to expose, not just a knob sweep.
"""
import os
import statistics as stats

from _bootstrap import RESULTS_DIR

from sealed_dispatch_eval.attackers import RouteJackingAttacker, SybilFloodAttacker
from sealed_dispatch_eval.crypto_stub import threshold_decrypt_latency_ms
from sealed_dispatch_eval.dispatch import dispatch_sealed
from sealed_dispatch_eval.metrics import win_rate, write_csv
from sealed_dispatch_eval.policy import select_winner
from sealed_dispatch_eval.pool import build_legit_pool, task_stream

N_TASKS = 300
N_LEGIT_BASE = 8
M_CANDIDATE_SET = 5
SYBIL_TOTAL_STAKE = 200.0
SYBIL_IDENTITIES = 20
REGISTRATION_RATE_PER_MS = 0.05  # extra legit registrants per ms of window
BASE_LATENCY_MS = 20.0

COMMITTEE_K_SWEEP = [1, 3, 5, 7]
COMMITTEE_M = 11
CANDIDACY_WINDOW_SWEEP_MS = [10.0, 30.0, 60.0, 120.0, 240.0]


def run_one(k_committee: int, window_ms: float, sybil_total_stake: float = SYBIL_TOTAL_STAKE) -> float:
    extra_legit = int(REGISTRATION_RATE_PER_MS * window_ms)
    legit = build_legit_pool(N_LEGIT_BASE + extra_legit, seed=42)
    mean_stake = stats.mean(p.stake for p in legit)

    sybil = SybilFloodAttacker(total_stake=sybil_total_stake, num_identities=SYBIL_IDENTITIES)
    sybil_ids = sybil.spawn_identities()
    sybil_id_set = {p.provider_id for p in sybil_ids}

    rj = RouteJackingAttacker(stake=mean_stake)
    tasks = task_stream(N_TASKS, num_categories=2, seed=7)

    outcomes = []
    for task in tasks:
        rj_listing = rj.craft_listing(task, visibility="coarse", price_ceiling=task.price_ceiling)
        adversary_ids = sybil_id_set | {rj_listing.provider_id}
        providers = legit + sybil_ids + [rj_listing]
        result = dispatch_sealed(
            task, providers, adversary_ids,
            m=M_CANDIDATE_SET, sampling_mode="stake_weighted",
            k_committee=k_committee, m_committee=COMMITTEE_M,
            nonce=f"epoch-{task.task_id // 50}",
        )
        # Reconnaissance signal is the legit-only market at this task's ceiling, as in exp1/exp2.
        # (Observing the dispatch winner instead would feed the attacker its own winning score
        # back and ratchet its target up by epsilon per win.)
        _, legit_best = select_winner([(p.provider_id, *p.claim()) for p in legit], task.price_ceiling)
        rj.observe(task, visibility="coarse", winning_score=legit_best)
        outcomes.append(result.adversary_won)

    return win_rate(outcomes)


def main():
    rows = []
    for k in COMMITTEE_K_SWEEP:
        for window_ms in CANDIDACY_WINDOW_SWEEP_MS:
            delta = run_one(k, window_ms)
            latency = BASE_LATENCY_MS + window_ms + threshold_decrypt_latency_ms(k, COMMITTEE_M)
            rows.append({
                "k_committee": k,
                "candidacy_window_ms": window_ms,
                "total_latency_ms": round(latency, 2),
                "adversary_win_rate": round(delta, 4),
            })
            print(f"k={k:>2} window={window_ms:>6.0f}ms  latency={latency:>7.2f}ms  delta={delta:.3f}")

    write_csv(os.path.join(RESULTS_DIR, "exp4_pareto_committee_window.csv"), rows)

    stake_fraction_sweep()


# Fixed, representative (k, window) point for the stake-fraction sweep below -- the mid-range of the
# grid above, chosen so this sweep isolates ONE variable (adversary stake fraction) instead of adding
# a third axis to the full k*window grid, matching exp5(b)'s isolation-of-one-variable design.
FIXED_K_FOR_STAKE_SWEEP = 5
FIXED_WINDOW_FOR_STAKE_SWEEP = 60.0
STAKE_FRACTION_SWEEP = [0.05, 0.1, 0.25, 0.5, 1.0, 2.0]  # same fractions as exp5(b), for direct comparison


def stake_fraction_sweep():
    """Closes the gap flagged in eval/README.md: the main sweep above only
    ever tests SYBIL_TOTAL_STAKE=200 (~1/3 of the legit pool) -- a
    deliberate stress case, not the typical operating point. This sweeps
    adversary stake fraction directly, holding (k, window) fixed, so the
    more common lower-stake-adversary regime is measured too, not just
    asserted to look better by extrapolation from the stress case."""
    extra_legit = int(REGISTRATION_RATE_PER_MS * FIXED_WINDOW_FOR_STAKE_SWEEP)
    total_legit_stake = sum(p.stake for p in build_legit_pool(N_LEGIT_BASE + extra_legit, seed=42))
    latency = (BASE_LATENCY_MS + FIXED_WINDOW_FOR_STAKE_SWEEP
               + threshold_decrypt_latency_ms(FIXED_K_FOR_STAKE_SWEEP, COMMITTEE_M))

    rows = []
    print(f"\nstake-fraction sweep at k={FIXED_K_FOR_STAKE_SWEEP}, window={FIXED_WINDOW_FOR_STAKE_SWEEP}ms:")
    for frac in STAKE_FRACTION_SWEEP:
        s_adv = frac * total_legit_stake
        delta = run_one(FIXED_K_FOR_STAKE_SWEEP, FIXED_WINDOW_FOR_STAKE_SWEEP, sybil_total_stake=s_adv)
        rows.append({
            "s_adv_frac_of_legit": frac,
            "s_adv": round(s_adv, 2),
            "k_committee": FIXED_K_FOR_STAKE_SWEEP,
            "candidacy_window_ms": FIXED_WINDOW_FOR_STAKE_SWEEP,
            "total_latency_ms": round(latency, 2),
            "adversary_win_rate": round(delta, 4),
        })
        print(f"  s_adv/legit={frac:>5.2f}  s_adv={s_adv:>9.2f}  delta={delta:.3f}")

    write_csv(os.path.join(RESULTS_DIR, "exp4_sybil_stake_fraction_sweep.csv"), rows)


if __name__ == "__main__":
    main()
