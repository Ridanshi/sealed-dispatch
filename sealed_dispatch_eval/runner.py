"""One Route-Jacking run, shared by the scale/adaptive and defense-comparison experiments.

A run is a stream of tasks against one legitimate pool and one honest Route-Jacking listing per task.
Returns the attacker's win rate, price per win and revenue per task, plus the agent's regret: how much
score the agent loses against scoring every provider (legitimate pool plus the listing). Regret is the cost
side of any defense that restricts or randomizes which bids are considered."""
import statistics as stats
from dataclasses import dataclass
from typing import Optional

from .attackers import FeedbackRouteJackingAttacker, RegressionRouteJackingAttacker, RouteJackingAttacker
from .dispatch import dispatch_baseline, dispatch_sealed
from .policy import select_winner
from .pool import build_bazaar_pool, build_legit_pool, task_stream

ATTACKERS = {"bucket_max": RouteJackingAttacker, "regression": RegressionRouteJackingAttacker,
             "feedback": FeedbackRouteJackingAttacker}


@dataclass(frozen=True)
class RunConfig:
    pool: str = "bazaar"           # 'synthetic' or 'bazaar'
    n_legit: int = 50
    attacker: str = "bucket_max"
    view: str = "full"             # 'full', 'coarse', 'category'
    selection: str = "all_scored"  # 'all_scored' or 'stake_m'
    m: int = 5
    n_cat: int = 2
    tau: float = 0.0               # near-tie lottery width, 0 = deterministic
    recon_rate: float = 1.0
    agent_weights: Optional[tuple] = None  # agent's true (price, quality, latency) weights; attacker assumes defaults
    n_tasks: int = 500
    seed: int = 0


def run(cfg: RunConfig):
    build = build_bazaar_pool if cfg.pool == "bazaar" else build_legit_pool
    legit = build(cfg.n_legit, seed=42 + cfg.seed)
    kw = {"stake": stats.mean(p.stake for p in legit)}
    if cfg.recon_rate < 1.0:
        kw.update(recon_rate=cfg.recon_rate, seed=cfg.seed)
    rj = ATTACKERS[cfg.attacker](**kw)
    wins, prices, regrets = 0, [], []
    for task in task_stream(cfg.n_tasks, cfg.n_cat, seed=7 + cfg.seed):
        listing = rj.craft_listing(task, cfg.view, task.price_ceiling)
        adv = {listing.provider_id}
        everyone = legit + [listing]
        if cfg.selection == "all_scored":
            res = dispatch_baseline(task, everyone, adv, tau=cfg.tau, weights=cfg.agent_weights)
        else:
            res = dispatch_sealed(task, everyone, adv, cfg.m, "stake_weighted", 3, 5,
                                  f"s{cfg.seed}-{task.task_id // 50}", tau=cfg.tau, weights=cfg.agent_weights)
        rj.feedback(res.adversary_won)
        _, best_all = select_winner([(p.provider_id, *p.claim()) for p in everyone], task.price_ceiling,
                                    weights=cfg.agent_weights)
        regrets.append(max(best_all - res.winning_score, 0.0))
        if res.adversary_won:
            wins += 1
            prices.append(listing.true_price)
        _, best = select_winner([(p.provider_id, *p.claim()) for p in legit], task.price_ceiling)
        rj.observe(task, cfg.view, best)
    ppw = stats.mean(prices) if prices else 0.0
    n = cfg.n_tasks
    return {"win_rate": wins / n, "price_per_win": ppw, "revenue": wins / n * ppw,
            "regret": stats.mean(regrets)}
