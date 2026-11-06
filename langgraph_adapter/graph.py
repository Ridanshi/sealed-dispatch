"""Builds the compiled LangGraph: parse_request -> dispatch -> execute -> settle -> END."""
from langgraph.graph import END, StateGraph

from .llm_task_parser import heuristic_parse
from .nodes import dispatch_node, execute_node, make_parse_request_node, settle_node
from .state import AgentState


def build_graph(parse_fn=heuristic_parse):
    """parse_fn: (request: str, task_id: int) -> TaskQuery. Defaults to
    the offline heuristic parser; pass llm_task_parser.make_llm_parse_fn(model)
    to use a real chat model instead -- see that module's docstring."""
    g = StateGraph(AgentState)
    g.add_node("parse_request", make_parse_request_node(parse_fn))
    g.add_node("dispatch", dispatch_node)
    g.add_node("execute", execute_node)
    g.add_node("settle", settle_node)

    g.set_entry_point("parse_request")
    g.add_edge("parse_request", "dispatch")
    g.add_edge("dispatch", "execute")
    g.add_edge("execute", "settle")
    g.add_edge("settle", END)

    return g.compile()
