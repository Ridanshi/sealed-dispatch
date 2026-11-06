"""Closes threat-model gap A4 (THREAT-MODEL.md §2, "racing the
post-decryption dispatch") -- previously asserted as "solvable with
existing point-to-point auth" without the harness actually enforcing
it. This experiment demonstrates the closure concretely:

1. provider_identity.self_test() -- the winner opens its own reveal
   correctly; a racer with a different keypair correctly fails.
2. A direct simulation: N tasks, a real winner and a real A4 racer
   (network-level, wins the "race" -- i.e. receives the sealed blob
   first, exactly the capability A4 is defined to have) both attempt to
   open the reveal. Reports the racer's success rate, which should be
   exactly 0 -- winning the network race no longer implies obtaining
   the plaintext.
3. Real measured latency overhead of sealing + opening one reveal, so
   this closure's cost is accounted for rather than assumed free.
"""
import os
import time

from _bootstrap import RESULTS_DIR

from sealed_dispatch_eval.metrics import write_csv
from sealed_dispatch_eval.provider_identity import (
    generate_identity,
    open_sealed,
    seal_for_provider,
    self_test,
)
from cryptography.exceptions import InvalidTag

N_TASKS = 200


def racer_attack_simulation(n_tasks: int = N_TASKS):
    """For each task: a winner is chosen, the committee seals the query
    for the winner's public key, and BOTH the real winner and an A4
    racer (who intercepted the same wire bytes -- sealing doesn't hide
    that a message was sent, only its content) attempt to open it."""
    racer_successes = 0
    winner_successes = 0

    for i in range(n_tasks):
        winner = generate_identity()
        racer = generate_identity()
        plaintext = f"task-{i}-query".encode()

        sealed = seal_for_provider(plaintext, winner.public_key)

        try:
            recovered = open_sealed(sealed, winner.private_key)
            winner_successes += int(recovered == plaintext)
        except InvalidTag:
            pass

        try:
            open_sealed(sealed, racer.private_key)
            racer_successes += 1  # would mean A4 closure failed
        except InvalidTag:
            pass  # correctly denied

    return winner_successes / n_tasks, racer_successes / n_tasks


def benchmark_seal_open_latency_ms(n_trials: int = 200) -> float:
    identity = generate_identity()
    durations = []
    for i in range(n_trials):
        plaintext = f"task-{i}-query-benchmark".encode()
        start = time.perf_counter()
        sealed = seal_for_provider(plaintext, identity.public_key)
        open_sealed(sealed, identity.private_key)
        durations.append((time.perf_counter() - start) * 1000.0)
    durations.sort()
    return durations[len(durations) // 2]  # median, same rationale as threshold_bls benchmarks


def main():
    ok = self_test()
    print(f"provider_identity self-test: {'PASS' if ok else 'FAIL'}")
    if not ok:
        raise RuntimeError("provider_identity.self_test() failed -- A4 closure is not actually working")

    winner_rate, racer_rate = racer_attack_simulation()
    print(f"winner open success rate:  {winner_rate:.4f}  (expect 1.0)")
    print(f"A4 racer open success rate: {racer_rate:.4f}  (expect 0.0 -- this IS the closure)")

    latency_ms = benchmark_seal_open_latency_ms()
    print(f"real measured seal+open latency (median): {latency_ms:.4f} ms")

    rows = [{
        "n_tasks": N_TASKS,
        "winner_open_success_rate": winner_rate,
        "a4_racer_open_success_rate": racer_rate,
        "a4_closed": racer_rate == 0.0 and winner_rate == 1.0,
        "seal_open_latency_ms_median": round(latency_ms, 4),
    }]
    write_csv(os.path.join(RESULTS_DIR, "exp8_a4_authenticated_reveal.csv"), rows)


if __name__ == "__main__":
    main()
