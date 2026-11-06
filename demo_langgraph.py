"""End-to-end LangGraph demo of Sealed Dispatch vs the plaintext baseline.

Reuses the exact same pool/attacker/dispatch code the experiments/
scripts measure against -- this script is a trace/demo, not a new
measurement. Run:

    python demo_langgraph.py
"""
import statistics as stats

from langgraph_adapter.graph import build_graph
from langgraph_adapter.llm_task_parser import heuristic_parse
from sealed_dispatch_eval.attackers import RouteJackingAttacker
from sealed_dispatch_eval.pool import build_legit_pool
from sealed_dispatch_eval.provider_identity import generate_identity

SAMPLE_REQUESTS = [
    "Please translate this document to Japanese, budget $50 max.",
    "Generate an image of a mountain landscape at sunset, $30 limit.",
    "Write a Python script to parse this CSV file.",
]


def run_demo():
    legit = build_legit_pool(8, seed=42)
    mean_stake = stats.mean(p.stake for p in legit)
    attacker = RouteJackingAttacker(stake=mean_stake)
    graph = build_graph()

    for mode in ("baseline", "sealed"):
        print(f"\n{'=' * 70}\nmode = {mode}\n{'=' * 70}")
        for request in SAMPLE_REQUESTS:
            # The graph's parse_request node always calls heuristic_parse
            # with task_id=0 for a fresh state (task_id = len(log) at
            # entry). Recompute the same task here, outside the graph,
            # purely so the attacker can craft its listing against the
            # real category/price_ceiling this request will resolve to --
            # not a stand-in for the graph's own parsing step.
            real_task = heuristic_parse(request, task_id=0)
            visibility = "full" if mode == "baseline" else "coarse"
            listing = attacker.craft_listing(
                real_task, visibility=visibility, price_ceiling=real_task.price_ceiling
            )
            providers = legit + [listing]
            # Every bonded provider (adversary listing included -- A4's
            # closure doesn't care who wins fairly, only that a network
            # racer other than the actual winner can't steal the reveal)
            # has a registered identity, per provider_identity.py.
            provider_identities = {p.provider_id: generate_identity() for p in providers}

            state = {
                "request": request,
                "providers": providers,
                "adversary_ids": {listing.provider_id},
                "mode": mode,
                "sealed_params": {"m": 5, "sampling_mode": "stake_weighted",
                                   "k_committee": 3, "m_committee": 5},
                "provider_identities": provider_identities,
                "log": [],
            }
            final_state = graph.invoke(state)

            print(f"\nrequest: {request!r}")
            for line in final_state["log"]:
                print(f"  {line}")

    print(
        "\n(this is a small-sample trace for illustration -- the actual win-rate/"
        "latency statistics this protocol is evaluated on live in results/*.csv, "
        "produced by experiments/, not by this demo.)"
    )


if __name__ == "__main__":
    run_demo()
