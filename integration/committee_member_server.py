"""One threshold-BLS committee member as an MCP server (stdio). Holds a single Shamir share.

Environment: MEMBER_IDX, MEMBER_SHARE (hex), MEMBER_MODE in {ok, slow, byz}, MEMBER_DELAY_MS.
A crashed member is modeled by not starting the process at all."""
import asyncio
import os
import sys

_EVAL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _EVAL not in sys.path:
    sys.path.insert(0, _EVAL)

import py_arkworks_bls12381 as ark
from mcp.server.fastmcp import FastMCP

from sealed_dispatch_eval.threshold_bls import DST_MESSAGE

IDX = int(os.environ["MEMBER_IDX"])
SHARE = int(os.environ["MEMBER_SHARE"], 16)
MODE = os.environ.get("MEMBER_MODE", "ok")
DELAY = float(os.environ.get("MEMBER_DELAY_MS", "0")) / 1000.0

mcp = FastMCP(f"committee-member-{IDX}")


@mcp.tool()
async def partial_sign(message_hex: str) -> dict:
    if MODE == "slow":
        await asyncio.sleep(DELAY)
    msg = bytes.fromhex(message_hex)
    if MODE == "byz":
        point = ark.G2Point.hash_to_curve(b"garbage-" + msg, DST_MESSAGE) * ark.Scalar(12345)
    else:
        point = ark.G2Point.hash_to_curve(msg, DST_MESSAGE) * ark.Scalar(SHARE)
    return {"idx": IDX, "partial": bytes(point.to_compressed_bytes()).hex()}


if __name__ == "__main__":
    mcp.run("stdio")
