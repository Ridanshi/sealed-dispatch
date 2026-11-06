"""A tool provider exposed as a real MCP server (stdio transport, official `mcp` SDK).

One process per provider. Environment:
  PROVIDER_IDX   index into build_legit_pool(8, seed=42), which fixes stake and true attributes
  X402_PAID      "1" to put an x402 paywall (Base Sepolia, exact scheme) on execute_sealed
  X402_PAY_TO    payee address when paid
  X402_PRICE     price string, default "$0.001"
  X402_FACILITATOR  facilitator URL, default https://x402.org/facilitator

Tools:
  register()                      stake and X25519 public key (the bonded identity, THREAT-MODEL §4.1)
  bid_coarse(category, band)      blind candidacy: the provider sees only the coarse view
  bid_full(query_json)            plaintext baseline: the provider sees the whole query
  execute_sealed(sealed_hex)      Reveal + Execute: opens the sealed box with its own key
  observed()                      what this provider has seen, per call (the exposure measurement)
"""
import json
import hashlib
import os
import sys

_EVAL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _EVAL not in sys.path:
    sys.path.insert(0, _EVAL)

from cryptography.exceptions import InvalidTag
from mcp.server.fastmcp import FastMCP

from sealed_dispatch_eval.pool import build_legit_pool
from sealed_dispatch_eval.provider_identity import generate_identity, open_sealed

IDX = int(os.environ.get("PROVIDER_IDX", "0"))
PAID = os.environ.get("X402_PAID") == "1"

_pool = build_legit_pool(8, seed=42)
_me = _pool[IDX]
_identity = generate_identity()
_seen = []

mcp = FastMCP(f"provider-{IDX}")


@mcp.tool()
def register() -> dict:
    return {"idx": IDX, "stake": _me.stake, "public_key": _identity.public_bytes.hex()}


@mcp.tool()
def bid_coarse(category: str, price_band: int) -> dict:
    _seen.append({"tool": "bid_coarse", "fields": ["category", "price_band"]})
    price, quality, latency = _me.claim()
    return {"idx": IDX, "price": price, "quality": quality, "latency_ms": latency}


@mcp.tool()
def bid_full(query_json: str) -> dict:
    q = json.loads(query_json)
    _seen.append({"tool": "bid_full", "fields": sorted(q.keys())})
    price, quality, latency = _me.claim()
    return {"idx": IDX, "price": price, "quality": quality, "latency_ms": latency}


def _run_task(sealed_hex: str) -> str:
    try:
        plaintext = open_sealed(bytes.fromhex(sealed_hex), _identity.private_key)
    except (InvalidTag, ValueError):
        _seen.append({"tool": "execute_sealed", "fields": [], "opened": False})
        return json.dumps({"idx": IDX, "opened": False})
    q = json.loads(plaintext)
    _seen.append({"tool": "execute_sealed", "fields": sorted(q.keys()), "opened": True})
    return json.dumps({"idx": IDX, "opened": True,
                       "result": hashlib.sha256(plaintext).hexdigest()[:16]})


if PAID:
    from x402 import x402ResourceServer
    from x402.http import FacilitatorConfig, HTTPFacilitatorClient
    from x402.mcp import create_payment_wrapper
    from x402.mechanisms.evm.exact import ExactEvmServerScheme
    from x402.schemas import ResourceInfo
    from x402.schemas.config import ResourceConfig

    NETWORK = "eip155:84532"
    facilitator = HTTPFacilitatorClient(FacilitatorConfig(
        url=os.environ.get("X402_FACILITATOR", "https://x402.org/facilitator")))
    resource_server = x402ResourceServer(facilitator)
    resource_server.register(NETWORK, ExactEvmServerScheme())
    resource_server.initialize()
    accepts = resource_server.build_payment_requirements(ResourceConfig(
        scheme="exact", network=NETWORK, pay_to=os.environ["X402_PAY_TO"],
        price=os.environ.get("X402_PRICE", "$0.001")))
    paid = create_payment_wrapper(
        resource_server, accepts=accepts,
        resource=ResourceInfo(url="mcp://tool/execute_sealed", description="Execute a sealed task",
                              mime_type="application/json"))

    @mcp.tool(name="execute_sealed", description="Open a sealed task and run it (x402-paid)")
    @paid
    async def execute_sealed(sealed_hex: str) -> str:
        return _run_task(sealed_hex)
else:
    @mcp.tool(name="execute_sealed", description="Open a sealed task and run it")
    def execute_sealed(sealed_hex: str) -> str:
        return _run_task(sealed_hex)


@mcp.tool()
def observed() -> dict:
    return {"log": _seen}


if __name__ == "__main__":
    mcp.run("stdio")
