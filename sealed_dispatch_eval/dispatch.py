"""End-to-end dispatch flows: baseline (plaintext, THREAT-MODEL.md §3)
vs Sealed Dispatch (§4). Both return a DispatchResult so experiments
compare apples to apples.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from . import crypto_stub
from .entities import Provider, TaskQuery
from .policy import select_winner, select_winner_lottery
from .provider_identity import ProviderIdentity, open_sealed, seal_for_provider
from .registry import sample_candidate_set


@dataclass
class DispatchResult:
    winner_id: int
    winning_score: float
    adversary_won: bool
    latency_ms: float
    pool_size: int
    reveal_authenticated: Optional[bool] = None  # None = not exercised this call (see dispatch_sealed)


def dispatch_baseline(task: TaskQuery, providers: List[Provider],
                       adversary_ids: Set[int],
                       base_latency_ms: float = 20.0, tau: float = 0.0, weights=None) -> DispatchResult:
    """Plaintext registry (§3): full query visible, every registered
    provider is scored directly — no bounded candidate-set sampling, which
    is exactly what lets Route-Jacking and Sybil-flood both work freely."""
    bids = []
    for p in providers:
        price, quality, latency = p.claim()
        bids.append((p.provider_id, price, quality, latency))
    if tau > 0:
        # the plaintext registry has no beacon: its lottery seed is derived from public task data
        winner_id, winning_score = select_winner_lottery(bids, task.price_ceiling, tau, task.task_id * 2654435761,
                                                         weights=weights)
    else:
        winner_id, winning_score = select_winner(bids, task.price_ceiling, weights=weights)
    return DispatchResult(
        winner_id=winner_id if winner_id is not None else -1,
        winning_score=winning_score or 0.0,
        adversary_won=(winner_id in adversary_ids) if winner_id is not None else False,
        latency_ms=base_latency_ms,
        pool_size=len(providers),
    )


def dispatch_sealed(task: TaskQuery, providers: List[Provider], adversary_ids: Set[int],
                     m: int, sampling_mode: str, k_committee: int, m_committee: int,
                     nonce: str,
                     base_latency_ms: float = 20.0,
                     candidacy_window_ms: float = 30.0,
                     provider_identities: Optional[Dict[int, ProviderIdentity]] = None,
                     tau: float = 0.0, weights=None) -> DispatchResult:
    """Sealed Dispatch (§4): a bounded candidate set of size m is sampled
    — stake-weighted if sampling_mode == 'stake_weighted' (§4.1) — using
    only the coarse task view (category + price band), before anyone is
    scored on the real query.

    `provider_identities`, if given (a {provider_id: ProviderIdentity}
    map), exercises the real Reveal-step authentication that closes
    threat-model gap A4 (provider_identity.py): the query is sealed to
    the winner's own public key, then "the winner" opens it, proving the
    plaintext only ever reaches the intended recipient. Optional and
    off by default (None) so the many-thousand-draw statistical
    experiments (exp1/2/4/5) don't pay a real crypto cost per call for a
    property those experiments aren't measuring — see crypto_stub.py's
    docstring for the same reasoning applied to vrf_seed. Experiments
    that DO want this exercised (the LangGraph demo; exp8 in isolation)
    pass a real identity map."""
    query_repr = str(sorted(task.coarse_view().items()))
    # the commitment binds this task (the real protocol commits to the encrypted query with fresh randomness), so
    # two tasks with the same coarse view in one epoch still get independent candidate sets
    commit = crypto_stub.commit_hash(f"{task.task_id}|{query_repr}", nonce)

    candidates = sample_candidate_set(providers, m, sampling_mode, commit, nonce)

    bids = []
    for p in candidates:
        price, quality, latency = p.claim()
        bids.append((p.provider_id, price, quality, latency))

    decrypt_latency = crypto_stub.threshold_decrypt_latency_ms(k_committee, m_committee)
    total_latency = base_latency_ms + candidacy_window_ms + decrypt_latency

    if tau > 0:
        # lottery seed comes from the beacon-derived commit/nonce, unpredictable before Lock
        winner_id, winning_score = select_winner_lottery(bids, task.price_ceiling, tau,
                                                         int(crypto_stub.vrf_seed(commit, nonce + 'lottery')),
                                                         weights=weights)
    else:
        winner_id, winning_score = select_winner(bids, task.price_ceiling, weights=weights)

    reveal_authenticated = None
    if provider_identities is not None and winner_id is not None and winner_id in provider_identities:
        identity = provider_identities[winner_id]
        sealed = seal_for_provider(query_repr.encode(), identity.public_key)
        recovered = open_sealed(sealed, identity.private_key)
        reveal_authenticated = recovered == query_repr.encode()

    return DispatchResult(
        winner_id=winner_id if winner_id is not None else -1,
        winning_score=winning_score or 0.0,
        adversary_won=(winner_id in adversary_ids) if winner_id is not None else False,
        latency_ms=total_latency,
        pool_size=len(candidates),
        reveal_authenticated=reveal_authenticated,
    )
