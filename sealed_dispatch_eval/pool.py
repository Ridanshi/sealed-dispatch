"""Helpers for building a legitimate provider pool and a task stream,
shared across experiments 1-4."""
import csv
import os
import random
from typing import List

from .entities import Provider, TaskQuery, new_provider_id


def build_legit_pool(n: int, seed: int = 0, mean_stake: float = 50.0) -> List[Provider]:
    rng = random.Random(seed)
    return [
        Provider(
            provider_id=new_provider_id(),
            stake=max(rng.gauss(mean_stake, mean_stake * 0.3), 1.0),
            true_price=rng.uniform(20, 80),
            true_quality=rng.uniform(0.6, 0.95),
            true_latency_ms=rng.uniform(50, 500),
            lie_strength=0.0,
        )
        for _ in range(n)
    ]


_BAZAAR_CSV = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data",
                           "x402_bazaar_prices.csv")


def bazaar_price_units() -> List[float]:
    """Real x402 Bazaar prices (USDC) rescaled so the median maps to 50 model price units, the middle of the
    synthetic pool's 20-80 range. Only the *shape* of the price distribution is taken from the data."""
    with open(_BAZAAR_CSV, newline="") as f:
        usd = sorted(float(r["usd_price"]) for r in csv.DictReader(f) if float(r["usd_price"]) > 0)
    med = usd[len(usd) // 2]
    return [50.0 * p / med for p in usd]


def build_bazaar_pool(n: int, seed: int = 0, mean_stake: float = 50.0) -> List[Provider]:
    """Like build_legit_pool, but prices are bootstrap-resampled from real x402 Bazaar listings (clipped to
    [1, 150] model units). Quality, latency and stake are still synthetic: the Bazaar does not publish them."""
    rng = random.Random(seed)
    prices = bazaar_price_units()
    return [
        Provider(
            provider_id=new_provider_id(),
            stake=max(rng.gauss(mean_stake, mean_stake * 0.3), 1.0),
            true_price=min(max(rng.choice(prices), 1.0), 150.0),
            true_quality=rng.uniform(0.6, 0.95),
            true_latency_ms=rng.uniform(50, 500),
            lie_strength=0.0,
        )
        for _ in range(n)
    ]


def task_stream(n_tasks: int, num_categories: int, seed: int = 1) -> List[TaskQuery]:
    rng = random.Random(seed)
    categories = [f"cat{i}" for i in range(num_categories)]
    tasks = []
    for i in range(n_tasks):
        cat = rng.choice(categories)
        tasks.append(TaskQuery(
            task_id=i,
            category=cat,
            price_ceiling=rng.uniform(40, 100),
            quality_floor=rng.uniform(0.5, 0.8),
        ))
    return tasks
