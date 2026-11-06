"""Fetch a sample of live x402 Bazaar listings (public discovery API) and keep only price-relevant fields.

Output: x402_bazaar_prices.csv with columns usd_price, network, scheme, desc_len. Payee addresses and
descriptions are not stored. Prices are USDC amounts converted from 6-decimal base units.
"""
import csv
import json
import random
import time
import urllib.request

BASE = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources"
PAGE, N_PAGES, TOTAL_HINT = 100, 60, 34524


def get(offset):
    req = urllib.request.Request(f"{BASE}?limit={PAGE}&offset={offset}",
                                 headers={"User-Agent": "python-httpx/0.28.1", "Accept": "application/json"})
    for attempt in range(4):
        try:
            return json.load(urllib.request.urlopen(req, timeout=40))
        except Exception:
            time.sleep(2 * (attempt + 1))
    return None


def main():
    rng = random.Random(0)
    offsets = sorted(rng.sample(range(0, TOTAL_HINT - PAGE, PAGE), N_PAGES))  # spread across the whole listing
    rows, total = [], None
    for off in offsets:
        d = get(off)
        if not d:
            continue
        total = d["pagination"]["total"]
        for it in d["items"]:
            for acc in it.get("accepts", [])[:1]:
                try:
                    usd = int(acc["amount"]) / 1e6
                except (KeyError, ValueError):
                    continue
                rows.append({"usd_price": usd, "network": acc.get("network"), "scheme": acc.get("scheme"),
                             "desc_len": len(it.get("description") or "")})
    with open("x402_bazaar_prices.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["usd_price", "network", "scheme", "desc_len"])
        w.writeheader()
        w.writerows(rows)
    print("listings in registry:", total, " sampled:", len(rows))


if __name__ == "__main__":
    main()
