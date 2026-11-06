"""Agent selection policy pi: scores bids, picks a winner.

A single fixed weighting is used throughout the eval harness so results
are comparable across experiments. Real deployments would let each agent
carry its own weights; that's an orthogonal axis, not varied here.
"""
from typing import List, Tuple

W_PRICE, W_QUALITY, W_LATENCY = 0.4, 0.4, 0.2
PRICE_CEILING_DEFAULT = 100.0
LATENCY_CEILING_DEFAULT = 2000.0


def score(price: float, quality: float, latency_ms: float,
          price_ceiling: float = PRICE_CEILING_DEFAULT,
          latency_ceiling: float = LATENCY_CEILING_DEFAULT,
          weights=None) -> float:
    """Higher is better. Each term normalized to [0, 1] before weighting. `weights` is an optional
    (price, quality, latency) triple; the default is the harness-wide 0.4 / 0.4 / 0.2."""
    wp, wq, wl = weights if weights is not None else (W_PRICE, W_QUALITY, W_LATENCY)
    price_term = 1 - min(price / price_ceiling, 1.0)
    quality_term = min(quality, 1.0)
    latency_term = 1 - min(latency_ms / latency_ceiling, 1.0)
    return wp * price_term + wq * quality_term + wl * latency_term


def select_winner_lottery(bids: List[Tuple[int, float, float, float]], price_ceiling: float,
                          tau: float, seed: int, weights=None):
    """Near-tie lottery: every bid whose score is within `tau` of the best is equally eligible, and the
    winner is drawn with a seed that comes from the committee beacon, so nobody can predict or bias it.
    The agent gives up at most `tau` of score; tau = 0 is the deterministic policy."""
    if not bids:
        return None, None
    scored = sorted(((score(p, q, l, price_ceiling, weights=weights), pid) for pid, p, q, l in bids),
                    reverse=True)
    best = scored[0][0]
    pool = [t for t in scored if t[0] >= best - tau]
    idx = seed % len(pool)
    return pool[idx][1], pool[idx][0]


def select_winner(bids: List[Tuple[int, float, float, float]],
                  price_ceiling: float = PRICE_CEILING_DEFAULT, weights=None):
    """bids: (provider_id, price, quality, latency_ms) tuples.
    `price_ceiling` is the task's own ceiling (TaskQuery.price_ceiling): the agent normalizes
    price against the budget of the task at hand, so the same bids score differently on
    different tasks. (An earlier version always normalized against the default ceiling, which
    made the legitimate best score identical on every task and left the attacker nothing
    query-specific to learn; see PAPER.md §11.)
    Returns (winner_id, winning_score), or (None, None) if bids is empty."""
    if not bids:
        return None, None
    scored = [(score(p, q, l, price_ceiling, weights=weights), pid) for pid, p, q, l in bids]
    scored.sort(reverse=True, key=lambda t: t[0])
    best_score, winner_id = scored[0]
    return winner_id, best_score
