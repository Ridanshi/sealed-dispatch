"""Threshold-BLS beacon from a committee of separate MCP server processes.

Five member processes (k = 3 of n = 5), each holding one Shamir share. The aggregator asks all members for a
partial signature on a fresh message, verifies each partial against the member's public key, and produces the
beacon from the first k valid ones. Compared with an aggregator that waits for every member (or for a timeout).

Conditions (members are real processes; a crashed member is simply not started):
  healthy       all five answer immediately
  1_unresponsive  member 5 accepts the call and never answers within the timeout (a crashed or partitioned node)
  1_byzantine   member 1 returns an invalid partial
  2_slow        members 1 and 2 answer after 300 ms
  2_slow_1_unresponsive  members 1 and 2 are slow (300 ms), member 5 is unresponsive
Timeout for the wait-for-all aggregator: 1000 ms. 20 beacons per condition and strategy.
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

import py_arkworks_bls12381 as ark
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from run_mcp_dispatch import parse, _leaves
from sealed_dispatch_eval.threshold_bls import ThresholdBLSCommittee

K, N, TRIALS, TIMEOUT_S, SLOW_MS, HANG_MS = 3, 5, 20, 1.0, 300, 2000
CONDITIONS = {
    "healthy": {},
    "1_unresponsive": {5: "hang"},
    "1_byzantine": {1: "byz"},
    "2_slow": {1: "slow", 2: "slow"},
    "2_slow_1_unresponsive": {1: "slow", 2: "slow", 5: "hang"},
}


async def run_condition(committee, name, modes):
    async with AsyncExitStack() as stack:
        sessions = {}
        for i in range(1, N + 1):
            mode = modes.get(i, "ok")
            delay = SLOW_MS
            if mode == "hang":  # accepts the connection and never answers within the timeout
                mode, delay = "slow", HANG_MS
            env = {**os.environ, "MEMBER_IDX": str(i), "MEMBER_SHARE": format(committee.shares[i], "x"),
                   "MEMBER_MODE": mode, "MEMBER_DELAY_MS": str(delay)}
            params = StdioServerParameters(command=sys.executable,
                                           args=[os.path.join(HERE, "committee_member_server.py")], env=env)
            r, w = await stack.enter_async_context(stdio_client(params, errlog=open(os.devnull, 'w')))
            s = await stack.enter_async_context(ClientSession(r, w))
            await s.initialize()
            sessions[i] = s

        async def ask(i, msg):
            res = await sessions[i].call_tool("partial_sign", {"message_hex": msg.hex()})
            d = parse(res)
            return i, ark.G2Point.from_compressed_bytes(bytes.fromhex(d["partial"]))

        out = {}
        for strategy in ("wait_all", "first_k_valid"):
            lat, ok = [], 0
            for t in range(TRIALS):
                msg = f"beacon-{name}-{strategy}-{t}".encode()
                t0 = time.perf_counter()
                tasks = [asyncio.ensure_future(ask(i, msg)) for i in sessions]
                valid, rejected = {}, 0
                if strategy == "wait_all":
                    done, _ = await asyncio.wait(tasks, timeout=TIMEOUT_S)
                    for d in done:
                        i, part = d.result()
                        if committee.verify_partial(i, msg, part):
                            valid[i] = part
                        else:
                            rejected += 1
                    if len(valid) >= K:
                        sig = committee.combine(valid)
                else:
                    for fut in asyncio.as_completed(tasks, timeout=TIMEOUT_S):
                        try:
                            i, part = await fut
                        except asyncio.TimeoutError:
                            break
                        if committee.verify_partial(i, msg, part):
                            valid[i] = part
                        else:
                            rejected += 1
                        if len(valid) >= K:
                            break
                    if len(valid) >= K:
                        sig = committee.combine(valid)
                good = len(valid) >= K and committee.verify(msg, sig)
                ok += int(good)
                lat.append((time.perf_counter() - t0) * 1000)
                # let stragglers finish outside the timed region; cancelling an in-flight MCP call breaks the stream
                await asyncio.gather(*tasks, return_exceptions=True)
            out[strategy] = (ok / TRIALS, stats.median(lat), sorted(lat)[int(0.95 * len(lat)) - 1])
        return out


async def main():
    committee = ThresholdBLSCommittee(K, N)
    rows = []
    for name, modes in CONDITIONS.items():
        res = await run_condition(committee, name, modes)
        for strategy, (succ, med, p95) in res.items():
            rows.append({"condition": name, "strategy": strategy, "beacons": TRIALS,
                         "success_rate": round(succ, 3), "latency_ms_median": round(med, 1),
                         "latency_ms_p95": round(p95, 1)})
            print(rows[-1], flush=True)
    path = os.path.join(EVAL, "results", "exp18_distributed_committee.csv")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except BaseExceptionGroup as eg:
        import traceback
        for leaf in _leaves(eg):
            traceback.print_exception(leaf, limit=-5)
        raise SystemExit(1)
