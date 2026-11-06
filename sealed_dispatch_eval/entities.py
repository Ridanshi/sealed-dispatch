"""Core data structures. Mirrors THREAT-MODEL.md §1 (system model)."""
from dataclasses import dataclass, field
import itertools

_id_counter = itertools.count(1)


def new_provider_id() -> int:
    return next(_id_counter)


@dataclass
class Provider:
    """A tool/service provider. `true_*` is ground truth. `lie_strength`
    (0 = always truthful) controls how much `claim()` misreports it --
    kept as a per-provider property, deliberately separate from whatever
    set of providers an experiment calls "the adversary" for win-rate
    bookkeeping. Route-Jacking (THREAT-MODEL.md §3) needs an *honest*
    adversary whose only edge is information asymmetry, not fabricated
    attributes; conflating the two previously let a truthful
    information-advantage attack get free rein to also lie, masking the
    effect being measured."""
    provider_id: int
    stake: float
    true_price: float
    true_quality: float
    true_latency_ms: float
    lie_strength: float = 0.0

    def claim(self):
        """Return (price, quality, latency_ms) as stated in a bid."""
        if self.lie_strength <= 0.0:
            return self.true_price, self.true_quality, self.true_latency_ms
        ls = self.lie_strength
        price = self.true_price * (1 - 0.5 * ls)
        quality = self.true_quality + (1 - self.true_quality) * ls
        latency = self.true_latency_ms * (1 - 0.5 * ls)
        return max(price, 0.01), min(quality, 1.0), max(latency, 1.0)


@dataclass
class TaskQuery:
    """A dispatch task. `exact_features` is what a plaintext registry
    exposes in full; `coarse_view()` is what Sealed Dispatch's blind
    candidacy phase exposes instead (THREAT-MODEL.md §4 step 2)."""
    task_id: int
    category: str
    price_ceiling: float
    quality_floor: float
    exact_features: dict = field(default_factory=dict)

    def coarse_view(self, n_price_bands: int = 4):
        band = min(int(self.price_ceiling // (100 / n_price_bands)), n_price_bands - 1)
        return {"category": self.category, "price_band": band}
