"""Settle a Sealed Dispatch execution through x402 on Base Sepolia.

The winner's execute_sealed tool (a real MCP server, see provider_server.py) sits behind the official
x402 payment wrapper: scheme "exact", network eip155:84532, USDC, facilitator https://x402.org/facilitator.
The orchestrator holds a throwaway test wallet (wallet.py) and pays through the x402 MCP client.

What each stage proves:
  1. unpaid call      the server answers with a real x402 PaymentRequired (price, asset, payTo)
  2. payment payload  the client signs an EIP-3009 transferWithAuthorization with the test key
  3. verify           the server asks the public facilitator to verify the signed payload
  4. settle           on success the facilitator submits the transfer; the response carries the tx hash

Stage 4 needs Base Sepolia test USDC at the payer address. This script reads the payer's balance from a
public RPC first and reports exactly which stage it reached. It never tries to obtain faucet funds itself.

Usage:  python run_x402_testnet.py
"""
import asyncio
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL = os.path.dirname(HERE)
sys.path.insert(0, EVAL)
sys.path.insert(0, HERE)

from eth_account import Account
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from x402 import x402Client
from x402.mcp import x402MCPSession
from x402.mechanisms.evm.exact import ExactEvmClientScheme
from x402.mechanisms.evm.signers import EthAccountSigner

from run_mcp_dispatch import parse, _leaves
from sealed_dispatch_eval.provider_identity import seal_for_provider
import wallet

NETWORK = "eip155:84532"
USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
RPC = "https://sepolia.base.org"
PRICE = "$0.001"
OUT = os.path.join(EVAL, "results", "exp12_x402_testnet.json")


def usdc_balance(address: str):
    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(RPC, request_kwargs={"timeout": 20}))
        abi = [{"constant": True, "inputs": [{"name": "a", "type": "address"}], "name": "balanceOf",
                "outputs": [{"name": "", "type": "uint256"}], "type": "function"}]
        c = w3.eth.contract(address=Web3.to_checksum_address(USDC_BASE_SEPOLIA), abi=abi)
        return c.functions.balanceOf(Web3.to_checksum_address(address)).call() / 1e6
    except Exception as e:  # network or RPC problem: report, do not guess
        return f"unavailable ({type(e).__name__})"


async def main():
    w = wallet.load_or_create()
    report = {"network": NETWORK, "price": PRICE, "payer": w["payer_address"], "payee": w["payee_address"],
              "payer_usdc_balance_before": usdc_balance(w["payer_address"])}
    print("payer USDC balance (Base Sepolia):", report["payer_usdc_balance_before"])

    env = {**os.environ, "PROVIDER_IDX": "0", "X402_PAID": "1", "X402_PAY_TO": w["payee_address"],
           "X402_PRICE": PRICE}
    params = StdioServerParameters(command=sys.executable,
                                   args=[os.path.join(HERE, "provider_server.py")], env=env)
    async with stdio_client(params) as (r, wr):
        async with ClientSession(r, wr) as session:
            await session.initialize()
            reg = parse(await session.call_tool("register", {}))
            pub = X25519PublicKey.from_public_bytes(bytes.fromhex(reg["public_key"]))
            sealed = seal_for_provider(json.dumps({"category": "cat0", "price_ceiling": 55.0,
                                                   "task_id": 1}).encode(), pub).hex()

            # 1. unpaid call
            raw = await session.call_tool("execute_sealed", {"sealed_hex": sealed})
            text = raw.content[0].text if raw.content else ""
            report["stage1_unpaid_is_error"] = bool(raw.isError)
            try:
                pr = json.loads(text)
                acc = (pr.get("accepts") or [{}])[0]
                report["stage1_payment_required"] = {
                    "x402Version": pr.get("x402Version"), "scheme": acc.get("scheme"),
                    "network": acc.get("network"), "amount": acc.get("amount"),
                    "asset": acc.get("asset"), "payTo": acc.get("payTo")}
            except json.JSONDecodeError:
                report["stage1_payment_required"] = text[:300]
            print("stage 1 (unpaid):", report["stage1_payment_required"])

            # 2-4. paid call
            pc = x402Client()
            pc.register(NETWORK, ExactEvmClientScheme(EthAccountSigner(Account.from_key(w["payer_private_key"]))))
            x = x402MCPSession(session, pc, auto_payment=True)
            t0 = time.perf_counter()
            try:
                res = await x.call_tool("execute_sealed", {"sealed_hex": sealed})
                report["paid_call_seconds"] = round(time.perf_counter() - t0, 2)
                pay = getattr(res, "payment_response", None)
                report["stage4_payment_response"] = (pay.model_dump(by_alias=True) if hasattr(pay, "model_dump")
                                                     else str(pay))
                report["tool_result"] = [getattr(c, "text", str(c)) for c in (res.content or [])][:1]
                report["is_error"] = bool(getattr(res, "is_error", False))
            except Exception as e:
                report["paid_call_seconds"] = round(time.perf_counter() - t0, 2)
                report["paid_call_exception"] = f"{type(e).__name__}: {str(e)[:400]}"
    report["payer_usdc_balance_after"] = usdc_balance(w["payer_address"])
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(report, f, indent=1, default=str)
    print(json.dumps(report, indent=1, default=str))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except BaseExceptionGroup as eg:
        import traceback
        for leaf in _leaves(eg):
            traceback.print_exception(leaf, limit=-5)
        raise SystemExit(1)
