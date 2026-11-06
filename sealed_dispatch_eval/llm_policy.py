"""An LLM agent as the selection policy pi (local model through Ollama).

Status: not used for any reported result. On the machine used for this work only 1.5B and 3B models fit in memory;
they agreed with the scoring formula on 5/30 and 2/30 tasks (mean rank of the choice 3.1 and 4.5 of 8, chance 3.5),
so they are not meaningful agents. The harness is kept so a larger model can be dropped in.

The agent sees the task (category, budget ceiling, minimum quality) and the listings that reach it
(price, quality, latency) in a randomized order, and returns the listing it prefers. It is not told the
harness's scoring formula. A heuristic attacker that tunes listings to that formula is therefore aiming at
an approximation of the agent's real preferences, which is the situation a real front-runner is in."""
import json
import random
import urllib.request

OLLAMA = "http://localhost:11434/api/chat"
MODEL = "qwen2.5:3b-instruct"


def _chat(prompt: str, model: str = MODEL, timeout: int = 120):
    body = json.dumps({
        "model": model, "stream": False, "format": "json",
        "options": {"temperature": 0, "seed": 7, "num_predict": 30, "num_ctx": 1024},
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(OLLAMA, data=body, headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=timeout))["message"]["content"]


def llm_select(task, bids, shuffle_seed: int, model: str = MODEL):
    """bids: (provider_id, price, quality, latency_ms). Returns provider_id (or None if unparsable)."""
    if not bids:
        return None
    order = list(bids)
    random.Random(shuffle_seed).shuffle(order)
    lines = [f"Option {i}: price {p:.1f}, quality {q:.2f}, latency {l:.0f} ms"
             for i, (_, p, q, l) in enumerate(order)]
    prompt = (
        "You are a procurement agent choosing one tool provider for a task.\n"
        f"Task category: {task.category}. Budget ceiling: {task.price_ceiling:.0f} (lower price is better, "
        f"must not exceed the ceiling). Minimum acceptable quality: {task.quality_floor:.2f} "
        "(higher quality is better). Lower latency is better.\n\n"
        + "\n".join(lines)
        + '\n\nPick the single best option overall. Reply with JSON only: {"choice": <option number>}.')
    try:
        raw = _chat(prompt, model).strip().strip("`")
        raw = raw[raw.index("{"): raw.rindex("}") + 1]
        idx = int(json.loads(raw)["choice"])
        return order[idx][0] if 0 <= idx < len(order) else None
    except Exception:
        return None
