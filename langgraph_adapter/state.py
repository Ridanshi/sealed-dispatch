"""Graph state schema.

Kept as a plain TypedDict (no reducers/annotations) -- each node returns
a full replacement for the keys it touches, which is enough for this
linear pipeline and keeps the adapter easy to audit against the protocol
docs. A branchier graph (parallel candidate solicitation, retries) would
want Annotated reducers; not needed for the single dispatch-decision
path modeled here.
"""
from typing import Any, List, Optional, Set, TypedDict

from sealed_dispatch_eval.dispatch import DispatchResult
from sealed_dispatch_eval.entities import Provider, TaskQuery
from sealed_dispatch_eval.provider_identity import ProviderIdentity


class AgentState(TypedDict, total=False):
    request: str                       # raw natural-language task request
    task: Optional[TaskQuery]           # parsed by nodes.parse_request
    providers: List[Provider]           # candidate pool for this task
    adversary_ids: Set[int]             # ground-truth attacker identities, for logging only --
                                         # never consulted by dispatch logic itself
    mode: str                           # "baseline" | "sealed"
    sealed_params: dict                 # m, sampling_mode, k_committee, m_committee, nonce
    provider_identities: dict           # {provider_id: ProviderIdentity} -- closes A4, see
                                         # provider_identity.py and dispatch_sealed's docstring
    dispatch_result: Optional[DispatchResult]
    winner: Optional[Provider]
    execution_output: Optional[str]
    settlement_status: Optional[str]
    log: List[str]
