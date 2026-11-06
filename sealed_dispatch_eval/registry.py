"""Candidate-set sampling for a task, in two modes (THREAT-MODEL.md §4.1).

- 'uniform_by_identity': naive baseline, every registered identity equally
  likely regardless of stake. This is the failure mode §4.1 argues
  against; kept here so exp5 can demonstrate why it's insufficient.
- 'stake_weighted': the actual §4.1 mechanism — inclusion probability
  proportional to bonded stake, drawn via a VRF-seeded RNG keyed on the
  task commitment so no bidder can predict or bias the draw in advance.
"""
import random
from typing import List

from .crypto_stub import vrf_seed
from .entities import Provider


def sample_candidate_set(providers: List[Provider], m: int, mode: str,
                          task_commit_hash: str, committee_nonce: str) -> List[Provider]:
    if not providers:
        return []
    m = min(m, len(providers))
    rng = random.Random(vrf_seed(task_commit_hash, committee_nonce))

    if mode == "uniform_by_identity":
        return rng.sample(providers, m)

    if mode == "stake_weighted":
        pool = list(providers)
        weights = [max(p.stake, 1e-9) for p in pool]
        chosen = []
        for _ in range(m):
            total = sum(weights)
            r = rng.uniform(0, total)
            acc = 0.0
            for i, w in enumerate(weights):
                acc += w
                if acc >= r:
                    chosen.append(pool.pop(i))
                    weights.pop(i)
                    break
        return chosen

    raise ValueError(f"unknown sampling mode: {mode!r}")
