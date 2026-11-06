"""Full-factorial ablation of the Sealed Dispatch defense components.

Earlier experiments toggle one mechanism at a time against one attack (exp2: blind
candidacy vs Route-Jacking; exp5: stake weighting vs a Sybil flood). This experiment
crosses them against the combined adversary, so interactions are measured instead of
inferred.

Factors:
  selection  how many bids are scored and how they are drawn
               all_scored  every registered provider is scored (no bounded candidate set)
               uniform_m   m candidates drawn uniformly by identity
               stake_m     m candidates drawn with probability proportional to bonded stake
  blind      attacker sees only the coarse view (category + price band) vs the full query
  slashing   a lying provider that wins is caught with probability P_DETECT and its stake is
             burned in full (ejected); the adversary's stake budget is not replenished
  reveal     authenticated reveal (sealed box to the winner's key) vs plain point-to-point

Adversary (the regression Route-Jacking attacker, the strongest of the three in exp14 when it sees the exact query): one honest Route-Jacking listing plus a 20-identity lying Sybil flood holding
S_ADV_FRAC of the legitimate stake. Metrics per configuration (mean and std over seeds):
  adv_win       adversary wins any task (Route-Jacking or Sybil)
  rj_win        Route-Jacking listing wins
  sybil_win     a Sybil identity wins
  adv_win_late  adv_win over the last quarter of the stream (shows the slashing effect)
  a4_exposure   share of tasks whose plaintext reaches an A4 racer that always wins the
                network race. Plain reveal leaks by construction; the authenticated reveal
                is measured with the real AEAD (a failed open by the racer counts as no leak).
"""
import os
import random
import statistics as stats

from _bootstrap import RESULTS_DIR

from cryptography.exceptions import InvalidTag

from sealed_dispatch_eval.attackers import RegressionRouteJackingAttacker as RouteJackingAttacker, SybilFloodAttacker
from sealed_dispatch_eval.dispatch import dispatch_baseline, dispatch_sealed
from sealed_dispatch_eval.metrics import mean_std, write_csv
from sealed_dispatch_eval.policy import select_winner
from sealed_dispatch_eval.pool import build_legit_pool, task_stream
from sealed_dispatch_eval.provider_identity import generate_identity, open_sealed, seal_for_provider

N_TASKS = 500
N_LEGIT = 8
NUM_CATEGORIES = 2
M_CANDIDATE_SET = 5
K_COMMITTEE, N_COMMITTEE = 3, 5
SYBIL_IDENTITIES = 20
S_ADV_FRAC = 0.5
P_DETECT = 0.5
SEEDS = list(range(10))
A4_RACE_TRIALS = 50  # real seal/open attempts per seed for the authenticated-reveal rows

SELECTIONS = ["all_scored", "uniform_m", "stake_m"]


def a4_exposure(reveal: str, rng_seed: int) -> float:
    if reveal == "plain":
        return 1.0
    leaked = 0
    for i in range(A4_RACE_TRIALS):
        winner, racer = generate_identity(), generate_identity()
        sealed = seal_for_provider(f"task-{rng_seed}-{i}".encode(), winner.public_key)
        try:
            open_sealed(sealed, racer.private_key)
            leaked += 1
        except InvalidTag:
            pass
    return leaked / A4_RACE_TRIALS


def run_config(selection: str, blind: bool, slashing: bool, seed: int):
    rng = random.Random(1000 + seed)
    legit = build_legit_pool(N_LEGIT, seed=42 + seed)
    total_legit = sum(p.stake for p in legit)
    mean_stake = stats.mean(p.stake for p in legit)
    sybils = SybilFloodAttacker(S_ADV_FRAC * total_legit, SYBIL_IDENTITIES).spawn_identities()
    sybil_ids = {p.provider_id for p in sybils}
    tasks = task_stream(N_TASKS, NUM_CATEGORIES, seed=7 + seed)
    rj = RouteJackingAttacker(stake=mean_stake)
    view = "coarse" if blind else "full"
    wins_rj = wins_sybil = wins_late = 0
    late_start = int(0.75 * N_TASKS)
    for task in tasks:
        listing = rj.craft_listing(task, view, task.price_ceiling)
        live_sybils = [p for p in sybils if p.stake > 0]
        providers = legit + live_sybils + [listing]
        adv_ids = sybil_ids | {listing.provider_id}
        if selection == "all_scored":
            res = dispatch_baseline(task, providers, adv_ids)
        else:
            mode = "stake_weighted" if selection == "stake_m" else "uniform_by_identity"
            res = dispatch_sealed(task, providers, adv_ids, M_CANDIDATE_SET, mode,
                                  K_COMMITTEE, N_COMMITTEE, f"s{seed}-epoch-{task.task_id // 50}")
        if res.winner_id == listing.provider_id:
            wins_rj += 1
        elif res.winner_id in sybil_ids:
            wins_sybil += 1
            if slashing and rng.random() < P_DETECT:
                for p in sybils:
                    if p.provider_id == res.winner_id:
                        p.stake = 0.0
        if res.adversary_won and task.task_id >= late_start:
            wins_late += 1
        _, legit_best = select_winner([(p.provider_id, *p.claim()) for p in legit], task.price_ceiling)
        rj.observe(task, view, legit_best)
    return (wins_rj + wins_sybil) / N_TASKS, wins_rj / N_TASKS, wins_sybil / N_TASKS, \
        wins_late / (N_TASKS - late_start)


def main():
    rows = []
    cell = {}
    for selection in SELECTIONS:
        for blind in (False, True):
            for slashing in (False, True):
                runs = [run_config(selection, blind, slashing, s) for s in SEEDS]
                adv, rjw, syw, late = (mean_std([r[i] for r in runs]) for i in range(4))
                cell[(selection, blind, slashing)] = adv[0]
                for reveal in ("plain", "authenticated"):
                    exposure = a4_exposure(reveal, 0)
                    rows.append({
                        "selection": selection, "blind_candidacy": blind, "slashing": slashing,
                        "reveal": reveal, "seeds": len(SEEDS),
                        "adv_win": round(adv[0], 4), "adv_win_std": round(adv[1], 4),
                        "rj_win": round(rjw[0], 4), "sybil_win": round(syw[0], 4),
                        "adv_win_late": round(late[0], 4), "a4_exposure": exposure,
                    })
                print(f"{selection:<10} blind={int(blind)} slash={int(slashing)}  "
                      f"adv={adv[0]:.3f}±{adv[1]:.3f} rj={rjw[0]:.3f} sybil={syw[0]:.3f} late={late[0]:.3f}")
    write_csv(os.path.join(RESULTS_DIR, "exp10_factorial_ablation.csv"), rows)

    # Drop-one from the full defense (stake_m + blind + slashing), and main effects.
    full = cell[("stake_m", True, True)]
    drops = [
        ("full defense", full),
        ("- slashing", cell[("stake_m", True, False)]),
        ("- blind candidacy", cell[("stake_m", False, True)]),
        ("- stake weighting (uniform_m)", cell[("uniform_m", True, True)]),
        ("- bounded candidate set (all_scored)", cell[("all_scored", True, True)]),
        ("nothing (plaintext baseline)", cell[("all_scored", False, False)]),
    ]
    drop_rows = [{"configuration": n, "adv_win": round(v, 4), "delta_vs_full": round(v - full, 4)} for n, v in drops]
    write_csv(os.path.join(RESULTS_DIR, "exp10_drop_one.csv"), drop_rows)
    for r in drop_rows:
        print(f"{r['configuration']:<40} adv_win={r['adv_win']:.3f}  vs full {r['delta_vs_full']:+.3f}")

    def avg(pred):
        v = [x for k, x in cell.items() if pred(k)]
        return sum(v) / len(v)

    effects = []
    for sel in SELECTIONS:
        effects.append({"factor": f"selection={sel}", "mean_adv_win": round(avg(lambda k: k[0] == sel), 4)})
    for name, idx in (("blind_candidacy", 1), ("slashing", 2)):
        for lvl in (False, True):
            effects.append({"factor": f"{name}={lvl}", "mean_adv_win": round(avg(lambda k: k[idx] == lvl), 4)})
    write_csv(os.path.join(RESULTS_DIR, "exp10_main_effects.csv"), effects)
    for e in effects:
        print(f"{e['factor']:<24} mean adv_win={e['mean_adv_win']:.3f}")


if __name__ == "__main__":
    main()
