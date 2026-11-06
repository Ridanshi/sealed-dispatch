# Sealed Dispatch: Eval Harness (current state)

**Read this first.** The numbers in the sections further down this file (the original "Findings so far") were
written before two harness flaws were fixed (price was scored against a constant ceiling, and the commitment did
not bind the task), and before the adaptive attackers, the Bazaar-calibrated pool and the dependability
experiments existed. The current numbers are in `results/*.csv` and in the paper
(`../docs/paper_tdsc/SealedDispatch_TDSC.docx`). `../docs/paper_tdsc/check_numbers.py` asserts every number the
paper quotes against these CSVs.

## Experiment catalog

| Script | Result files | What it measures |
|---|---|---|
| `exp1_baseline_vs_routejacking.py` | `exp1_*.csv` | Route-Jacking win rate vs query predictability, 20 seeds |
| `exp2_sealed_dispatch_defense.py` | `exp2_*.csv` | Plaintext vs Sealed Dispatch at two categories, 20 seeds |
| `exp3_latency_overhead.py`, `exp7_real_threshold_bls_benchmark.py` | `exp3_*.csv`, `exp7_*.csv` | Modeled latency overhead and measured BLS cost (timings vary up to 2x between runs) |
| `exp4_pareto_committee_window.py` | `exp4_*.csv` | Combined Route-Jacking plus lying-Sybil attack, committee size and window, stake sweep |
| `exp5_sybil_flood.py`, `exp6_slashing_condition.py` | `exp5_*.csv`, `exp6_*.csv` | Slot share vs identities and stake (Theorem 1), slashing EV vs Monte Carlo (Theorem 2) |
| `exp8_a4_authenticated_reveal.py` | `exp8_*.csv` | Sealed reveal against a racing adversary |
| `exp9_committee_fault_tolerance.py` | `exp9a..d_*.csv` | Liveness, invalid partials, safety/liveness trade, fallback policies, grinding |
| `exp10_factorial_ablation.py` | `exp10_*.csv` | Selection x blind candidacy x slashing against Route-Jacking plus Sybil |
| `exp14_scale_and_adaptive.py` | `exp14a_*.csv`, `exp14b_*.csv` | 3 attackers x 2 pools x 8-200 providers x views x selection; set-size and category sensitivity; agent regret |
| `exp15_defense_comparison.py` | `exp15_*.csv` | Bounded set, near-tie lottery, rate-limited recon, bid-first, worst case over attackers |
| `exp17_correlated_and_proactive.py` | `exp17a..c_*.csv` | Failure domains, adaptive corruption with proactive refresh, refresh crypto check |
| `exp19_preference_mismatch.py` | `exp19_*.csv` | Attacker tuned to default weights vs agents with other weights |
| `integration/run_mcp_dispatch.py` | `exp11_*` | Eight real MCP provider processes, 60 tasks, exposure and latency |
| `integration/run_x402_testnet.py` | `exp12_x402_testnet.json` | x402 payment on Base Sepolia (needs test USDC at the address from `integration/wallet.py`; set the faucet to Base Sepolia, not Arc Testnet) |
| `integration/run_distributed_committee.py` | `exp18_*.csv` | Threshold-BLS beacon from five committee-member processes under slow, unresponsive and Byzantine members |

`python run_all.py` runs exp1 to exp10, exp14, exp15, exp17 and exp19 (about 6 minutes on 16 cores). The integration
scripts are run separately. Dependencies: `requirements-crypto.txt`, plus `pip install mcp x402 web3 eth-account`
for `integration/`. `sealed_dispatch_eval/llm_policy.py` is a harness for a model-based selector that is not used
for any reported result (see its docstring).

---

# Sealed Dispatch — Eval Harness

Simulation harness for the protocol in [`../THREAT-MODEL.md`](../THREAT-MODEL.md). Models the
system at the protocol level (providers, registry, dispatch, attackers) so the security metrics
from §6 / §4.1 can be measured without depending on a specific LLM agent framework. Wiring this
into LangGraph/AutoGen for a live demo is a later, separate step and should not change any of
these numbers — they come from the dispatch/sampling/scoring logic, not from the LLM itself.

**Dependencies.** `dispatch.py` imports `provider_identity.py` (closes threat-model gap A4, see §5) at
module level, so the whole package now needs `cryptography` (a standard, usually-preinstalled library) —
this used to be a stdlib-only guarantee for exp1-6 and is not anymore, even though most of those
experiments never exercise the A4-closure feature itself (it's off by default, a `None` parameter, but
the *import* isn't optional). `threshold_bls.py` (and therefore exp7) additionally needs
`py_arkworks_bls12381`. See `requirements-crypto.txt` for both, with the reasoning for each.

## Run everything

```bash
cd eval
pip install -r requirements-crypto.txt   # needed for the whole harness now, not just exp7
python run_all.py
```

Writes one CSV per experiment to `results/`.

## What each experiment measures, and how it maps to the threat model

| Script | THREAT-MODEL.md ref | Question it answers |
|---|---|---|
| `exp1_baseline_vs_routejacking.py` | §6 item 2 | On the plaintext baseline, how does Route-Jacking's win rate scale with query predictability (category reuse)? |
| `exp2_sealed_dispatch_defense.py` | §6 item 4 | Does Sealed Dispatch's coarse candidacy view + bounded candidate-set sampling reduce that win rate, at the worst-case (most predictable) setting? |
| `exp3_latency_overhead.py` | §6 item 5 | What does Sealed Dispatch cost in latency, absolute and as % of a realistic end-to-end (LLM-inference-dominated) task? |
| `exp4_pareto_committee_window.py` | §6 item 6 | Security/latency Pareto frontier as committee size and candidacy window vary, under a *combined* Route-Jacking + Sybil-flood attack. |
| `exp5_sybil_flood.py` | §6 item 7 / §4.1 core claim | Does stake-weighted VRF sampling actually make expected slot-share track stake, not identity count — and does naive uniform-by-identity sampling fail exactly as predicted? |
| `exp6_slashing_condition.py` | §4.1 step 6 | Does the slashing viability condition hold numerically, checked against a Monte Carlo simulation of the underlying either/or lottery? |
| `exp4_pareto_committee_window.py`'s `stake_fraction_sweep()` | §6 item 6 (extended) | Does the Sybil win-rate finding hold across adversary stake fraction, not just the one large stress case the main sweep tests? Output: `exp4_sybil_stake_fraction_sweep.csv`. |
| `exp8_a4_authenticated_reveal.py` | §2 gap A4 | Does sealing the reveal to the winner's own registered key actually stop a network-racing adversary (A4) from obtaining the plaintext, even though it won the race? |
| `exp7_real_threshold_bls_benchmark.py` | §4 cost model | Does a correctness-verified, real BLS12-381 threshold-signature implementation match the latency numbers §4's cost model assumed? (Not the first backend tried — see findings below.) |

## Package layout

```
sealed_dispatch_eval/
  entities.py    Provider, TaskQuery (§1 system model)
  policy.py      agent scoring function pi
  crypto_stub.py fast commit-hash / VRF-seed stand-ins (deliberate, see module docstring) +
                 threshold_decrypt_latency_ms, which IS real-measured (fitted from exp7)
  registry.py    candidate-set sampling: uniform_by_identity vs stake_weighted (§4.1)
  dispatch.py    dispatch_baseline (§3) and dispatch_sealed (§4) end-to-end flows
  attackers.py   RouteJackingAttacker (§3), SybilFloodAttacker (§4.1), slashing EV helper
  pool.py        legit provider pool + task stream generators shared by exp1-4
  metrics.py     win_rate / mean_std / write_csv helpers
  threshold_bls.py  real BLS12-381 threshold signatures (py_arkworks_bls12381, Rust arkworks
                 bindings): Shamir-shared key, per-share partial signing, Lagrange combination,
                 self-test, sequential/parallel latency benchmarks. Backs the *measured* constants
                 in crypto_stub.py -- see exp7 and this module's own docstring for what it does
                 and, importantly, does NOT cover (query encryption/decryption is still
                 coarse_view()-based, not real threshold PKE/IBE) and for why the backend changed
                 from an earlier py_ecc (pure-Python reference) implementation.
  provider_identity.py  real X25519 sealed-box encryption (ephemeral ECDH + HKDF + ChaCha20Poly1305,
                 via `cryptography`): closes threat-model gap A4 by encrypting the Reveal-step
                 payload to the winner's own registered public key, so a network-racing adversary
                 who wins the race but isn't the real winner gets ciphertext, not the query. Wired
                 into dispatch_sealed as an optional (`None`-default) parameter -- see exp8.
```

## Findings so far (from the committed `results/` CSVs)

- **exp1**: delta drops from 0.878 (1 category, maximum reuse) to 0.116 (32 categories, essentially the
  0.111 no-information baseline) — Route-Jacking's power comes from repeated exposure to a predictable
  query distribution. (These are the numbers after the scoring fix described under "Scoring bug" below;
  the earlier 0.90 to 0.28 came from a harness whose legitimate best score was identical on every task.)
- **exp2**: at two categories, delta is 0.758 on the plaintext registry and 0.632 under Sealed Dispatch.
  **That reduction comes from bounded candidate sampling, not from the coarse view** (see exp13): with
  sampling held fixed the coarse view raises the attacker's win rate.
- **exp3**: current numbers (`results/exp3_latency_overhead.csv`) show **1.6-13.3% overhead** of a
  representative end-to-end task latency across k=1-11 — the "small tax" claim holds, now because it's
  backed by a real, fast (arkworks/Rust) threshold-BLS measurement, not because nobody checked. An
  earlier pass through this same file with a *slower* backend (py_ecc, pure-Python reference) measured
  26-47% overhead and looked like a real problem for the approach — see exp7's entry for why that
  number was real but not representative, and don't be surprised if this line's numbers move again if
  the backend changes once more (e.g. to `blst`).
- **exp4**: delta stays high (0.82-0.99) under a *large, lying* combined attacker even with stake-weighted
  sampling active. This is expected, not a defense failure: §4.1's sampling mechanism bounds slot
  *share*, not win probability *given* a slot — a lying Sybil that does get sampled still wins almost
  every time on fabricated attributes. That's exactly the gap slashing (exp6) is supposed to close, ex
  post; dispatch-time sampling and post-hoc slashing are two different layers of the same design and
  neither is meant to carry the whole security argument alone. Worth restating plainly in the paper
  rather than letting a reviewer read this number as "the defense doesn't work."
- **exp5**: the central §4.1 claim holds cleanly — stake-weighted slot share stays flat (~0.33-0.35)
  across identity counts 1 to 1000 at fixed adversary stake, while uniform-by-identity share climbs from
  0.05 to 0.98 over the same sweep. Sub-experiment (b) confirms linear scaling with stake share, and (c)
  confirms the capped free-tier bound holds regardless of new-registrant count.
- **exp7**: this cost model went through three real numbers, not one, and the history is worth keeping:
  (1) first-draft placeholder `base_ms=5.0, per_share_ms=1.5`, never benchmarked against anything;
  (2) benchmarked against `py_ecc` (pure-Python BLS12-381 reference implementation, correctness
  self-tested): `base_ms=239.08, per_share_ms=33.47` — ~30-40x higher than the placeholder, which flipped
  exp3's conclusion from "small tax" to "26-47% overhead," a real finding at the time;
  (3) rebenchmarked against `py_arkworks_bls12381` (Rust arkworks bindings, prebuilt wheel — `blspy`
  failed to build here for lack of a C++ toolchain, this one didn't need one): `base_ms=3.06,
  per_share_ms=0.27` — ~100x faster than the py_ecc number, restoring the "small tax" conclusion, now for
  real reasons. The reusable lesson: a correctness-verified reference implementation is not the same
  thing as a production-representative one, and the gap between them changed the paper's headline
  latency claim twice, not once. Keep this progression in the paper's evaluation section rather than
  quietly presenting only the final number — it's evidence the cost model was actually checked, not
  asserted.
- **exp6**: a real bug was caught and fixed here — the first-draft analytic slashing formula
  (`gain - gamma*stake*p_detect`) disagreed in *sign* with a direct Monte Carlo simulation of the
  underlying lottery on real parameter values (e.g. gamma=0.3, stake=100, p_detect=0.8, gain=50: first
  draft said +26 / profitable to lie, correct answer is -14 / deterred). Fixed in
  `sealed_dispatch_eval/attackers.py:slashing_expected_value` and in THREAT-MODEL.md §4.1 step 6; 0/125
  disagreements after the fix. Worth keeping this in the paper's evaluation section as a demonstration
  that the mechanism-design claims were actually checked, not just asserted.

## LangGraph adapter

`langgraph_adapter/` wires `dispatch_baseline` / `dispatch_sealed` behind real LangGraph nodes
(`parse_request -> dispatch -> execute -> settle -> END`). It is glue only — every number it produces
should be reproducible by calling `sealed_dispatch_eval` directly, the way `experiments/` already does.
If wiring the framework in ever changes a measured outcome, that's an adapter bug, not a new result.

```bash
pip install -r requirements-adapter.txt   # langgraph only; everything else here stays stdlib-only
python demo_langgraph.py
```

Task parsing (`llm_task_parser.py`) defaults to a deterministic keyword/regex heuristic — no API key
needed, runs offline/in CI. `llm_task_parser.make_llm_parse_fn(chat_model)` wraps a real LangChain-style
chat model with the same signature for a live demo; nothing downstream needs to change either way,
since the model's only job is producing the same `TaskQuery` shape the heuristic does.

The demo script's own traces are illustrative (3 sample requests) — real win-rate/latency numbers come
from `experiments/`'s CSVs, not from eyeballing a handful of demo runs. Worth restating in the paper's
prototype section rather than citing demo output as evidence.

## Known limitations / next steps

- `threshold_bls.py` now runs on `py_arkworks_bls12381` (Rust arkworks bindings, prebuilt wheel), swapped
  in after the first backend (`py_ecc`, pure-Python reference) turned out to be ~100x slower than a real
  deployment would be. `blst` (what production BLS deployments, e.g. Ethereum validators, actually run)
  is still one step further and failed to build here (`blspy`, no C++ toolchain on this machine) — worth
  one more try on a machine that has one, but arkworks is a real, fast, correct backend, not a stopgap.
- `threshold_bls.py` implements threshold *signatures* (a verifiable randomness beacon + unforgeable
  winner-attestation), not threshold *encryption/decryption* of the task query itself — that's still
  handled by `coarse_view()`, not real cryptography. A real deployment wanting genuine query
  confidentiality until the winner is locked would need a separate primitive (e.g. IBE-based timelock
  encryption over a drand-style beacon, `tlock`-style) — noted as future work, not silently assumed
  solved by adding BLS.
- ~~exp4's Sybil stake (200) is a large fraction (~1/3) of total pool stake~~ — **closed.**
  `stake_fraction_sweep()` in `exp4_pareto_committee_window.py` now sweeps adversary stake fraction
  directly (same fractions as exp5(b): 0.05-2.0x legit pool stake), holding (k, window) fixed at a
  representative point, output in `results/exp4_sybil_stake_fraction_sweep.csv`. Finding: delta stays
  high (0.72) even at the *smallest* fraction tested (0.05x) — this isn't a sampling-bound failure, it's
  the same composition point exp4's main sweep already made: once a lying adversary (Sybil or otherwise)
  lands a sampled slot, sampling bounds don't touch win-probability-given-a-slot at *any* scale. Slashing
  carries that part of the argument regardless of how small the adversary's stake is — worth stating
  plainly rather than implying scale is what made the original stress case look bad.
- LangGraph adapter (`langgraph_adapter/`) is wired and runnable (see above); AutoGen integration
  would be a second, separate adapter over the same `sealed_dispatch_eval` core if the paper wants to
  show framework-independence.
- `demo_langgraph.py`'s task parser is a keyword heuristic, not a real LLM call — sufficient to prove
  the wiring, not sufficient to claim the dispatch layer behaves correctly on ambiguous natural-language
  requests. Swapping in `llm_task_parser.make_llm_parse_fn` with a real model is the natural next check.

## Scoring bug found and fixed (read this before comparing against older results)

`policy.select_winner` used to normalize price against a constant ceiling (100) instead of the task's own
`price_ceiling`. The legitimate best score was therefore the same on every task (0.7737), so the coarse
view hid nothing, and `exp2`'s comment about a "blended max over many distinct exact-feature tasks" described
behaviour the code did not have. `select_winner` now takes the task ceiling, `dispatch_*` pass it, the
Route-Jacking attacker converts targets to prices with the band midpoint under the coarse view, and
`exp4` observes the legitimate-only best score instead of the dispatch winner (observing the winner fed the
attacker its own winning score back). Results changed for exp1, exp2 and exp9/exp10/exp13; exp3, exp4's
numbers, exp5, exp6, exp7 and exp8 did not.

## Fault tolerance, ablation, and real-system experiments

| Script | Question |
|---|---|
| `exp9_committee_fault_tolerance.py` | Liveness under crashes (closed form, Monte Carlo, real BLS), invalid partial signatures (naive vs verifying combiner), safety vs liveness as k varies, and four fallback policies under a degraded committee. Writes `exp9a..d_*.csv`. |
| `exp10_factorial_ablation.py` | Selection mode x blind candidacy x slashing against a combined Route-Jacking + Sybil adversary, 10 seeds; drop-one and main-effect tables. |
| `exp13_blind_candidacy_isolation.py` | Route-Jacking only: win rate, price per win and revenue per task for each selection mode x attacker view. |
| `integration/run_mcp_dispatch.py` | The protocol over eight real MCP provider servers (stdio): latency, exact-query exposure per task, A4 racer, beacon verification. Writes `exp11_*`. |
| `integration/run_x402_testnet.py` | The winner's tool behind the official x402 wrapper on Base Sepolia. Settles on Base Sepolia when the payer address printed by `integration/wallet.py` holds test USDC (the faucet must be set to Base Sepolia, not Arc Testnet); without funds it stops at `invalid_exact_evm_insufficient_balance`. Writes `exp12_x402_testnet.json`. |

Integration dependencies: `pip install mcp x402 web3 eth-account`. `integration/.testnet_wallet.json` holds a
throwaway testnet key and is git-ignored.
