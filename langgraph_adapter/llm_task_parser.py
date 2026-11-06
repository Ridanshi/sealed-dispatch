"""Turns a natural-language request into a TaskQuery.

Default implementation is a deterministic keyword heuristic -- no API
key needed, and it keeps the demo runnable offline / in CI. Swap in a
real model by passing a `parse_fn` with the same signature to
build_graph() (langgraph_adapter/graph.py); nothing else in the adapter
or in sealed_dispatch_eval needs to change, since the LLM's only job
here is producing the same TaskQuery shape a hand-written one would.
"""
import re
from typing import Callable, Optional

from sealed_dispatch_eval.entities import TaskQuery

TaskParseFn = Callable[[str, int], TaskQuery]

_CATEGORY_KEYWORDS = {
    "translate": "translation", "translation": "translation",
    "image": "image-gen", "picture": "image-gen", "photo": "image-gen",
    "code": "code-gen", "program": "code-gen", "script": "code-gen",
    "summarize": "summarization", "summary": "summarization",
    "search": "web-search", "lookup": "web-search",
}

_PRICE_RE = re.compile(r"\$?(\d+(?:\.\d+)?)\s*(?:usd|dollars)?\s*(?:max|ceiling|budget|limit)?", re.I)


def heuristic_parse(request: str, task_id: int) -> TaskQuery:
    """No model call: keyword match for category, regex for a price
    ceiling if one is mentioned, sane defaults otherwise. Deliberately
    simple -- it exists so the graph is runnable without any API key,
    not to be a good NL parser."""
    lower = request.lower()
    category = "general"
    for kw, cat in _CATEGORY_KEYWORDS.items():
        if kw in lower:
            category = cat
            break

    price_ceiling = 60.0
    m = _PRICE_RE.search(request)
    if m:
        try:
            price_ceiling = float(m.group(1))
        except ValueError:
            pass

    return TaskQuery(
        task_id=task_id, category=category,
        price_ceiling=price_ceiling, quality_floor=0.6,
    )


def make_llm_parse_fn(chat_model) -> TaskParseFn:
    """Wraps a LangChain-style chat model (anything with `.invoke(str) ->
    object with .content`) into a TaskParseFn. Not used unless the caller
    explicitly passes an instantiated model to build_graph() -- kept
    separate from heuristic_parse so tests/demos never accidentally need
    network access or an API key.

    Expects the model to return a short JSON-ish line; falls back to the
    heuristic parser on any parse failure rather than crashing the graph
    on a malformed model response.
    """
    import json

    def _parse(request: str, task_id: int) -> TaskQuery:
        prompt = (
            "Extract a tool-dispatch task spec as JSON with keys "
            "category (short slug), price_ceiling (number), quality_floor "
            "(0-1). Request: " + request
        )
        try:
            resp = chat_model.invoke(prompt)
            text = getattr(resp, "content", str(resp))
            data = json.loads(text)
            return TaskQuery(
                task_id=task_id,
                category=str(data.get("category", "general")),
                price_ceiling=float(data.get("price_ceiling", 60.0)),
                quality_floor=float(data.get("quality_floor", 0.6)),
            )
        except Exception:
            return heuristic_parse(request, task_id)

    return _parse
