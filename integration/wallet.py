"""Throwaway Base Sepolia test wallets for the x402 integration (testnet only, no real value).

Keys are generated locally, stored in integration/.testnet_wallet.json (listed in .gitignore),
and never printed. Only addresses are shown."""
import json
import os

from eth_account import Account

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".testnet_wallet.json")


def load_or_create() -> dict:
    if os.path.exists(_PATH):
        with open(_PATH) as f:
            return json.load(f)
    payer, payee = Account.create(), Account.create()
    data = {
        "network": "eip155:84532",
        "payer_private_key": payer.key.hex(),
        "payer_address": payer.address,
        "payee_address": payee.address,
    }
    with open(_PATH, "w") as f:
        json.dump(data, f)
    return data


if __name__ == "__main__":
    w = load_or_create()
    print("payer (fund this with Base Sepolia test USDC):", w["payer_address"])
    print("payee:", w["payee_address"])
