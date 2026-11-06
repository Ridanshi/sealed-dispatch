"""Attacker models.

RouteJackingAttacker implements the §3 attack: observe (some view of) the
task, learn what score tends to win in that bucket, craft one listing that
just beats it. Its `visibility` argument is the whole point of the
experiment — 'full' (plaintext baseline) vs 'coarse' (Sealed Dispatch's
blind candidacy view) — since that's exactly the information the defense
takes away.

SybilFloodAttacker implements the §4.1 attack: split a stake budget across
k identities to try to dominate candidate-set sampling by volume.
"""
import random
from typing import List

from .entities import Provider, TaskQuery, new_provider_id
from .policy import W_PRICE, W_QUALITY, W_LATENCY, LATENCY_CEILING_DEFAULT


class RouteJackingAttacker:
    """Learns per-bucket winning scores from observed outcomes, then crafts a single tuned listing to just
    beat the best one it has seen.

    `visibility` says what the attacker knows about the task being dispatched:
      'full'      the exact query (category and price ceiling)
      'coarse'    category and price band only (Sealed Dispatch's blind-candidacy view)
      'category'  category only (the bid-first baseline: bids are fixed before any task detail exists)
    `recon_rate` < 1 models a rate-limited reconnaissance channel: each task's legitimate best score is
    observed only with that probability."""

    def __init__(self, epsilon: float = 0.02, stake: float = 10.0, recon_rate: float = 1.0, seed: int = 0):
        self.best_known_score = {}
        self.epsilon = epsilon
        self.stake = stake
        self.recon_rate = recon_rate
        self._rng = random.Random(seed)

    def _bucket_key(self, task: TaskQuery, visibility: str) -> str:
        if visibility == "full":
            return f"full:{task.category}:{task.price_ceiling:.0f}"
        if visibility == "category":
            return f"category:{task.category}"
        coarse = task.coarse_view()
        return f"coarse:{coarse['category']}:{coarse['price_band']}"

    def _known_ceiling(self, task: TaskQuery, visibility: str, price_ceiling: float) -> float:
        """The price ceiling the attacker believes the task has, given what it can see."""
        if visibility == "full":
            return price_ceiling
        if visibility == "category":
            return 70.0  # midpoint of the public 40-100 ceiling range
        n_bands = 4
        return (task.coarse_view(n_bands)["price_band"] + 0.5) * (100 / n_bands)

    def observe(self, task: TaskQuery, visibility: str, winning_score: float):
        if self.recon_rate < 1.0 and self._rng.random() >= self.recon_rate:
            return
        key = self._bucket_key(task, visibility)
        prev = self.best_known_score.get(key, 0.0)
        self.best_known_score[key] = max(prev, winning_score)

    def feedback(self, won: bool):
        """Called after each dispatch with whether the listing won (the only outcome the attacker sees)."""

    def _target(self, task: TaskQuery, visibility: str) -> float:
        return self.best_known_score.get(self._bucket_key(task, visibility), 0.5) + self.epsilon

    def _listing(self, target_score: float, believed_ceiling: float) -> Provider:
        quality, latency = 0.95, 50.0
        remaining = target_score - W_QUALITY * quality - W_LATENCY * (1 - latency / LATENCY_CEILING_DEFAULT)
        price_term = max(0.0, min(1.0, remaining / W_PRICE))
        price = (1 - price_term) * believed_ceiling
        # lie_strength=0: Route-Jacking's edge is information asymmetry (knowing what score it needs to
        # hit), not fabricated attributes -- it commits to and would actually deliver this triple.
        return Provider(
            provider_id=new_provider_id(), stake=self.stake,
            true_price=max(price, 0.01), true_quality=quality, true_latency_ms=latency,
            lie_strength=0.0,
        )

    def craft_listing(self, task: TaskQuery, visibility: str, price_ceiling: float = 100.0) -> Provider:
        return self._listing(self._target(task, visibility),
                             self._known_ceiling(task, visibility, price_ceiling))


class RegressionRouteJackingAttacker(RouteJackingAttacker):
    """Fits, per category, best_score ~ a + b / ceiling on what it has observed and aims at the
    prediction plus its own residual spread plus epsilon. With the exact ceiling this extrapolates to
    ceilings it has never seen; with a band midpoint the regressor's input is noisy, which is exactly
    what the coarse view is meant to cause. Falls back to the bucket maximum until it has three points."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._obs = {}  # category -> list of (1/believed_ceiling, score)

    def observe(self, task, visibility, winning_score):
        if self.recon_rate < 1.0 and self._rng.random() >= self.recon_rate:
            return
        key = self._bucket_key(task, visibility)
        self.best_known_score[key] = max(self.best_known_score.get(key, 0.0), winning_score)
        c = self._known_ceiling(task, visibility, task.price_ceiling)
        self._obs.setdefault((visibility, task.category), []).append((1.0 / c, winning_score))

    def _target(self, task, visibility):
        base = super()._target(task, visibility)
        pts = self._obs.get((visibility, task.category), [])
        xs = {round(x, 6) for x, _ in pts}
        if len(pts) < 3 or len(xs) < 2:
            return base
        n = len(pts)
        mx = sum(x for x, _ in pts) / n
        my = sum(y for _, y in pts) / n
        sxx = sum((x - mx) ** 2 for x, _ in pts)
        b = sum((x - mx) * (y - my) for x, y in pts) / sxx if sxx > 0 else 0.0
        a = my - b * mx
        resid = [y - (a + b * x) for x, y in pts]
        sd = (sum(r * r for r in resid) / max(n - 2, 1)) ** 0.5
        c = self._known_ceiling(task, visibility, task.price_ceiling)
        return max(a + b / c + 2.0 * sd, 0.0) + self.epsilon


class FeedbackRouteJackingAttacker(RouteJackingAttacker):
    """Bucket-maximum targeting plus an adaptive margin: the margin grows after a loss and shrinks after
    a win, using only the win/loss feedback an attacker really gets."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.margin = self.epsilon

    def feedback(self, won: bool):
        if won:
            self.margin = max(self.epsilon, self.margin * 0.95)
        else:
            self.margin = min(0.4, self.margin + 0.01)

    def _target(self, task, visibility):
        return self.best_known_score.get(self._bucket_key(task, visibility), 0.5) + self.margin


class SybilFloodAttacker:
    """Splits a fixed total stake budget across `num_identities` Sybils,
    each bidding attractive (lied) attributes. Used to test whether
    identity count alone can win more candidate-set slots (THREAT-MODEL.md
    §4.1's central claim: it should not, under stake-weighted sampling)."""

    def __init__(self, total_stake: float, num_identities: int, lie_strength: float = 0.9):
        self.total_stake = total_stake
        self.num_identities = max(num_identities, 1)
        self.lie_strength = lie_strength

    def spawn_identities(self, true_quality: float = 0.5, true_price: float = 50.0,
                          true_latency_ms: float = 100.0) -> List[Provider]:
        stake_each = self.total_stake / self.num_identities
        return [
            Provider(
                provider_id=new_provider_id(), stake=stake_each,
                true_price=true_price, true_quality=true_quality,
                true_latency_ms=true_latency_ms, lie_strength=self.lie_strength,
            )
            for _ in range(self.num_identities)
        ]


def free_tier_weight(w0_max_pool: float, new_registrants_this_epoch: int) -> float:
    """§4.1 step 5: cold-start weight per new identity, diluted so the
    *total* free-tier budget stays capped regardless of how many new
    (potentially Sybil) identities show up in one epoch."""
    n = max(new_registrants_this_epoch, 1)
    return w0_max_pool / n


def slashing_expected_value(stake: float, gamma: float, p_detect: float,
                             fraudulent_gain: float) -> float:
    """THREAT-MODEL.md §4.1 step 6 viability condition, as an expected
    value: negative means lying is a losing bet in expectation.

    This is an either/or lottery, not two independent terms: the gain is
    only realized when the lie is *not* caught, and the slash is only
    paid when it *is* caught --

        EV(lie) = (1 - p_detect) * fraudulent_gain - p_detect * gamma * stake

    Slashing deters lying iff EV(lie) < 0, i.e.
        p_detect * gamma * stake > (1 - p_detect) * fraudulent_gain.

    (An earlier draft of this function and of THREAT-MODEL.md §4.1 used
    `fraudulent_gain - gamma*stake*p_detect`, which double-counts: it
    keeps the gain unconditionally *and* subtracts an expected slash,
    rather than weighting each outcome by the probability it actually
    occurs. The two formulas disagree in sign on real parameter values --
    caught by comparing against a direct Monte Carlo simulation of the
    lottery, not by inspection.)
    """
    return (1 - p_detect) * fraudulent_gain - p_detect * gamma * stake
