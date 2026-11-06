"""Graph nodes. Each is a plain function State -> partial State update,
per LangGraph convention. All protocol-level work is delegated straight
to sealed_dispatch_eval -- these functions only shuffle state and log.
"""
from sealed_dispatch_eval.dispatch import dispatch_baseline, dispatch_sealed

from .llm_task_parser import heuristic_parse
from .state import AgentState


def make_parse_request_node(parse_fn=heuristic_parse):
    """Factory so the parser is swappable per-graph (see llm_task_parser)
    without the node's call signature changing."""

    def parse_request(state: AgentState) -> AgentState:
        task = parse_fn(state["request"], task_id=len(state.get("log", [])))
        log = state.get("log", []) + [
            f"parse_request: {state['request']!r} -> category={task.category} "
            f"price_ceiling={task.price_ceiling:.1f}"
        ]
        return {"task": task, "log": log}

    return parse_request


def dispatch_node(state: AgentState) -> AgentState:
    """Runs the actual dispatch decision -- baseline or Sealed Dispatch,
    per state['mode'] -- using exactly the functions the eval experiments
    use. This is the one node the whole adapter exists to wire in."""
    task = state["task"]
    providers = state["providers"]
    adversary_ids = state.get("adversary_ids", set())
    mode = state.get("mode", "baseline")

    if mode == "baseline":
        result = dispatch_baseline(task, providers, adversary_ids)
    elif mode == "sealed":
        p = state.get("sealed_params", {})
        result = dispatch_sealed(
            task, providers, adversary_ids,
            m=p.get("m", 5),
            sampling_mode=p.get("sampling_mode", "stake_weighted"),
            k_committee=p.get("k_committee", 3),
            m_committee=p.get("m_committee", 5),
            nonce=p.get("nonce", f"nonce-{task.task_id}"),
            provider_identities=state.get("provider_identities"),
        )
    else:
        raise ValueError(f"unknown dispatch mode: {mode!r}")

    winner = next((p for p in providers if p.provider_id == result.winner_id), None)
    flag = " [ADVERSARY WON]" if result.adversary_won else ""
    reveal_note = ""
    if result.reveal_authenticated is not None:
        reveal_note = f" reveal_authenticated={result.reveal_authenticated}"
    log = state["log"] + [
        f"dispatch[{mode}]: winner_id={result.winner_id}{flag} "
        f"latency={result.latency_ms:.1f}ms pool_sampled={result.pool_size}{reveal_note}"
    ]
    return {"dispatch_result": result, "winner": winner, "log": log}


def execute_node(state: AgentState) -> AgentState:
    """Stands in for actually invoking the winning provider's tool/API.
    A real deployment would make the call here; this only records that
    it would have, since the eval harness's job is measuring the
    dispatch decision, not simulating tool execution semantics."""
    winner = state.get("winner")
    if winner is None:
        output = "no provider won dispatch -- nothing to execute"
    else:
        output = f"executed task on provider {winner.provider_id} (simulated)"
    return {"execution_output": output, "log": state["log"] + [f"execute: {output}"]}


def settle_node(state: AgentState) -> AgentState:
    """Placeholder for the settlement layer (x402 or equivalent) --
    THREAT-MODEL.md §1 scopes that layer as out of this protocol's
    novelty claim, so it's a no-op here beyond recording that dispatch
    handed off to it."""
    winner = state.get("winner")
    status = "settled (simulated)" if winner is not None else "skipped (no winner)"
    return {"settlement_status": status, "log": state["log"] + [f"settle: {status}"]}
