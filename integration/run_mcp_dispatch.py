"""Sealed Dispatch against real MCP servers.

Spawns eight provider MCP servers (stdio, official `mcp` SDK, one OS process each) and runs the same
task stream through two dispatchers over real MCP calls:

  plaintext   every provider receives the full query in bid_full and the best score wins
  sealed      Commit -> blind candidacy (bid_coarse, coarse view only) -> Lock (real threshold-BLS beacon
              seeds stake-weighted sampling of 5 candidates) -> Reveal (X25519 sealed box to the winner's
              registered key) -> Execute (execute_sealed on the winner)

Measured, not modeled:
  * wall-clock dispatch latency over local stdio MCP transport (compute plus protocol framing; no network)
  * exact-feature exposure: how many provider processes ever received the exact price ceiling, from each
    server's own log of what it saw
  * A4: the sealed blob is also sent to a non-winning provider; it must fail to open it
  * every beacon signature is verified against the committee public key
"""
import asyncio
import csv
import json
import os
import statistics as stats
import sys
import time
from contextlib import AsyncExitStack

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL = os.path.dirname(HERE)
sys.path.insert(0, EVAL)

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from sealed_dispatch_eval import crypto_stub
from sealed_dispatch_eval.policy import select_winner
from sealed_dispatch_eval.pool import build_legit_pool, task_stream
from sealed_dispatch_eval.provider_identity import seal_for_provider
from sealed_dispatch_eval.registry import sample_candidate_set
from sealed_dispatch_eval.threshold_bls import ThresholdBLSCommittee

N_PROVIDERS = 8
N_TASKS = 60
M_CANDIDATES = 5
K_COMMITTEE, N_COMMITTEE = 3, 5
RESULTS = os.path.join(EVAL, "results")


def parse(res):
    sc = getattr(res, "structuredContent", None)
    val = sc["result"] if sc and set(sc) == {"result"} else sc
    if val is None:
        val = res.content[0].text
    if isinstance(val, str):
        try:
            return json.loads(val)
        except json.JSONDecodeError:
            return val
    return val


async def spawn_providers(stack, extra_env=None):
    sessions = []
    for i in range(N_PROVIDERS):
        env = {**os.environ, "PROVIDER_IDX": str(i), **(extra_env or {})}
        params = StdioServerParameters(command=sys.executable,
                                       args=[os.path.join(HERE, "provider_server.py")], env=env)
        r, w = await stack.enter_async_context(stdio_client(params))
        s = await stack.enter_async_context(ClientSession(r, w))
        await s.initialize()
        sessions.append(s)
    return sessions


async def call(s, name, args=None):
    return parse(await s.call_tool(name, args or {}))


async def main():
    pool = build_legit_pool(N_PROVIDERS, seed=42)
    tasks = task_stream(N_TASKS, 2, seed=7)
    committee = ThresholdBLSCommittee(K_COMMITTEE, N_COMMITTEE)
    rows = []
    async with AsyncExitStack() as stack:
        sessions = await spawn_providers(stack)
        regs = [await call(s, "register") for s in sessions]
        for reg, p in zip(regs, pool):
            assert abs(reg["stake"] - p.stake) < 1e-9, "provider process and orchestrator disagree on stake"
        pubkeys = [X25519PublicKey.from_public_bytes(bytes.fromhex(r["public_key"])) for r in regs]
        idx_of = {p.provider_id: i for i, p in enumerate(pool)}
        tools = [t.name for t in (await sessions[0].list_tools()).tools]
        print("MCP tools exposed by each provider:", tools)

        # ---- plaintext baseline
        lat_plain = []
        for task in tasks:
            q = json.dumps({"category": task.category, "price_ceiling": task.price_ceiling,
                            "quality_floor": task.quality_floor, "task_id": task.task_id})
            t0 = time.perf_counter()
            bids = await asyncio.gather(*[call(s, "bid_full", {"query_json": q}) for s in sessions])
            winner, _ = select_winner([(b["idx"], b["price"], b["quality"], b["latency_ms"]) for b in bids],
                                      task.price_ceiling)
            sealed = seal_for_provider(q.encode(), pubkeys[winner])
            out = await call(sessions[winner], "execute_sealed", {"sealed_hex": sealed.hex()})
            assert out["opened"] and out["idx"] == winner
            lat_plain.append((time.perf_counter() - t0) * 1000)
        seen_plain = [(await call(s, "observed"))["log"] for s in sessions]
        exact_plain = sum(1 for log in seen_plain for e in log
                          if e["tool"] == "bid_full" and "price_ceiling" in e["fields"])
        providers_exact_plain = sum(1 for log in seen_plain
                                    if any("price_ceiling" in e["fields"] for e in log))

    # fresh processes so the sealed run's exposure log starts empty
    async with AsyncExitStack() as stack:
        sessions = await spawn_providers(stack)
        regs = [await call(s, "register") for s in sessions]
        pubkeys = [X25519PublicKey.from_public_bytes(bytes.fromhex(r["public_key"])) for r in regs]
        lat_sealed, lat_beacon, lat_bids, lat_exec = [], [], [], []
        a4_attempts = a4_opened = beacon_ok = 0
        for task in tasks:
            q = json.dumps({"category": task.category, "price_ceiling": task.price_ceiling,
                            "quality_floor": task.quality_floor, "task_id": task.task_id})
            coarse = task.coarse_view()
            t0 = time.perf_counter()
            commit = crypto_stub.commit_hash(str(sorted(coarse.items())), f"mcp-{task.task_id}")
            t1 = time.perf_counter()
            sig = committee.sign_with_k_of_n(commit.encode())
            beacon_ok += int(committee.verify(commit.encode(), sig))
            beacon_hex = sig.hex()
            t2 = time.perf_counter()
            bids = await asyncio.gather(*[call(s, "bid_coarse", {"category": coarse["category"],
                                                                  "price_band": coarse["price_band"]})
                                          for s in sessions])
            t3 = time.perf_counter()
            candidates = sample_candidate_set(pool, M_CANDIDATES, "stake_weighted", commit, beacon_hex)
            cand_idx = {idx_of[p.provider_id] for p in candidates}
            winner, _ = select_winner([(b["idx"], b["price"], b["quality"], b["latency_ms"])
                                       for b in bids if b["idx"] in cand_idx], task.price_ceiling)
            sealed = seal_for_provider(q.encode(), pubkeys[winner])
            out = await call(sessions[winner], "execute_sealed", {"sealed_hex": sealed.hex()})
            t4 = time.perf_counter()
            assert out["opened"] and out["idx"] == winner
            lat_sealed.append((t4 - t0) * 1000)
            lat_beacon.append((t2 - t1) * 1000)
            lat_bids.append((t3 - t2) * 1000)
            lat_exec.append((t4 - t3) * 1000)
            # A4 racer: another provider process gets the same ciphertext
            racer = next(i for i in range(N_PROVIDERS) if i != winner)
            leaked = await call(sessions[racer], "execute_sealed", {"sealed_hex": sealed.hex()})
            a4_attempts += 1
            a4_opened += int(leaked["opened"])
        seen_sealed = [(await call(s, "observed"))["log"] for s in sessions]
        exact_sealed = sum(1 for log in seen_sealed for e in log
                           if e["tool"] == "execute_sealed" and e.get("opened"))
        providers_exact_sealed = sum(1 for log in seen_sealed if any(e.get("opened") for e in log))
        coarse_only_leak = sum(1 for log in seen_sealed for e in log
                               if e["tool"] == "bid_coarse" and "price_ceiling" in e["fields"])

    def p(v, q):
        v = sorted(v)
        return v[min(int(q * len(v)), len(v) - 1)]

    rows = [
        {"mode": "plaintext", "tasks": N_TASKS, "latency_ms_median": round(stats.median(lat_plain), 2),
         "latency_ms_p95": round(p(lat_plain, 0.95), 2),
         "exact_price_ceiling_disclosures_per_task": round(exact_plain / N_TASKS, 3),
         "providers_that_saw_exact_query": providers_exact_plain, "a4_racer_opened": "n/a",
         "beacon_signatures_verified": "n/a"},
        {"mode": "sealed", "tasks": N_TASKS, "latency_ms_median": round(stats.median(lat_sealed), 2),
         "latency_ms_p95": round(p(lat_sealed, 0.95), 2),
         "exact_price_ceiling_disclosures_per_task": round(exact_sealed / N_TASKS, 3),
         "providers_that_saw_exact_query": providers_exact_sealed,
         "a4_racer_opened": f"{a4_opened}/{a4_attempts}",
         "beacon_signatures_verified": f"{beacon_ok}/{N_TASKS}"},
    ]
    detail = {
        "sealed_beacon_ms_median": round(stats.median(lat_beacon), 2),
        "sealed_blind_bids_ms_median": round(stats.median(lat_bids), 2),
        "sealed_reveal_execute_ms_median": round(stats.median(lat_exec), 2),
        "bid_coarse_calls_that_carried_exact_ceiling": coarse_only_leak,
    }
    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, "exp11_mcp_dispatch.csv")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(RESULTS, "exp11_mcp_dispatch_breakdown.json"), "w") as f:
        json.dump(detail, f, indent=1)
    for r in rows:
        print(r)
    print(detail)
    overhead = stats.median(lat_sealed) - stats.median(lat_plain)
    print(f"sealed minus plaintext median latency: {overhead:+.2f} ms")


def _leaves(e):
    if isinstance(e, BaseExceptionGroup):
        for x in e.exceptions:
            yield from _leaves(x)
    else:
        yield e


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except BaseExceptionGroup as eg:
        import traceback
        for leaf in _leaves(eg):
            traceback.print_exception(leaf, limit=-5)
        raise SystemExit(1)
