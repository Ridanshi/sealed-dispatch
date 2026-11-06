"""Real threshold BLS12-381 signatures (Shamir-shared secret key,
per-share partial signing, Lagrange combination) -- replacing the toy
`vrf_seed` hash stub in crypto_stub.py with an actual cryptographic
randomness-beacon primitive, and giving the "committee locks the
(task, winner) pairing" step in THREAT-MODEL.md §4 point 3 a real,
unforgeable k-of-m signature instead of a described-but-unimplemented
commitment.

Backend: `py_arkworks_bls12381` (Rust arkworks bindings, prebuilt wheel,
no C++ toolchain needed on this machine). This module previously ran on
`py_ecc` (the Ethereum Foundation's pure-Python reference
implementation) -- correct, but ~300x slower, which is exactly the
caveat that was attached to every latency number this module fed into.
Swapping the backend after already having a self-test and two benchmark
functions (sequential upper bound, parallel-realistic estimate) meant
the swap only had to prove it reproduces the same pass/fail behavior,
not redesign anything -- see self_test() and the exp7 experiment, which
now reports genuinely production-realistic numbers instead of a
reference-implementation pessimistic bound.

Cryptographic note on the verification equation: standard min-pubkey-
size BLS uses pk = sk * G1_GENERATOR with the IETF-standard generator
point, so pk bytes are interoperable with other BLS12-381 libraries.
This module instead derives its own fixed G1 basis point via
hash-to-curve (see _G1_BASIS below) rather than importing the standard
generator's coordinates. That is cryptographically sound -- the
security of a discrete-log-based scheme like this does not depend on
which fixed, public basis point is used, only that it IS fixed and
public, which _G1_BASIS is (deterministically derived, not secret,
recomputed identically by verify()) -- but it means signatures/pubkeys
produced here are NOT byte-interoperable with a standard BLS library's
pk/sig pair. Fine for this harness's internal sign+verify use; would
need reconciling with the canonical generator if this ever needed to
interoperate with an external BLS deployment.

Scope, stated precisely (do not oversell this beyond what it is): this
module gives two things real cryptographic weight:
  1. Verifiable, unpredictable-until-signed randomness for candidate-set
     sampling (a drand-style beacon: seed = H(threshold_signature)).
  2. An unforgeable k-of-m attestation over a committed value (e.g. a
     posted "task X -> provider p*" record).
It does NOT implement threshold *encryption/decryption* of the task
query itself -- BLS is a signature scheme, not a PKE scheme. Query
confidentiality during the candidacy phase is still handled by
coarse_view() (entities.py), not by this module. A real deployment
wanting genuine threshold decryption of the query (not just a
randomness beacon + attestation) would need a separate primitive, e.g.
IBE-based timelock encryption over a drand-style beacon (see tlock) --
noted as future work in THREAT-MODEL.md, not silently assumed solved.
"""
import hashlib
import secrets
import statistics
import time
from typing import Dict, List, Sequence

import py_arkworks_bls12381 as ark

# BLS12-381 subgroup order -- a public constant of the curve, not a secret.
ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513

# Domain-separation tags. DST_MESSAGE matches the standard BLS ciphersuite's
# tag (BLS12381G2_XMD:SHA-256_SSWU_RO_, POP variant) so message hashing
# follows the same IETF hash-to-curve construction other BLS libraries use,
# even though _G1_BASIS itself is non-standard (see module docstring).
DST_MESSAGE = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
_G1_BASIS_SEED = b"sealed-dispatch-g1-basis-v1"
_G1_BASIS = ark.G1Point.hash_to_curve(_G1_BASIS_SEED, DST_MESSAGE)


def _shamir_split(secret: int, k: int, n: int) -> List[tuple]:
    """Standard Shamir secret sharing over Z_ORDER: a degree-(k-1)
    polynomial with the secret as the constant term, evaluated at
    x = 1..n."""
    coeffs = [secret] + [secrets.randbelow(ORDER) for _ in range(k - 1)]

    def f(x: int) -> int:
        return sum(c * pow(x, i, ORDER) for i, c in enumerate(coeffs)) % ORDER

    return [(i, f(i)) for i in range(1, n + 1)]


def _lagrange_coeff(indices: Sequence[int], i: int) -> int:
    num, den = 1, 1
    for j in indices:
        if j == i:
            continue
        num = (num * (-j)) % ORDER
        den = (den * (i - j)) % ORDER
    return (num * pow(den, -1, ORDER)) % ORDER


class ThresholdBLSCommittee:
    """A k-of-n committee holding Shamir shares of a single BLS secret
    key. Any k members' partial signatures on the same message combine
    (via Lagrange interpolation in the exponent) into the identical
    valid signature the un-split master key would have produced --
    standard property of BLS's linearity, not something specific to
    this implementation."""

    def __init__(self, k: int, n: int, seed_material: bytes = None):
        self.k = k
        self.n = n
        if seed_material:
            # Hash first, don't reduce raw input mod ORDER directly -- short
            # or low-entropy seed_material would otherwise map unevenly
            # (and predictably) onto the scalar field.
            sk = int.from_bytes(hashlib.sha256(seed_material).digest(), "big") % ORDER
        else:
            sk = secrets.randbelow(ORDER)
        self.pk = _G1_BASIS * ark.Scalar(sk)
        self.shares: Dict[int, int] = dict(_shamir_split(sk, k, n))
        # Public per-member verification keys pk_i = share_i * basis. In a
        # real deployment these come out of the DKG; they let anyone check
        # a single partial signature before combining (see verify_partial).
        self.member_pks: Dict[int, "ark.G1Point"] = {
            i: _G1_BASIS * ark.Scalar(sh) for i, sh in self.shares.items()
        }
        # sk itself is intentionally not retained beyond this constructor
        # -- nothing downstream should need the reconstructed master key.

    def refresh(self) -> None:
        """Proactive share refresh (Herzberg-style): every member deals a random degree-(k-1) polynomial
        with zero constant term, and each member adds the evaluations it receives to its share. The secret
        and the public key are unchanged; shares from before and after a refresh do not combine, so shares an
        adversary stole in an earlier epoch become useless. Dealing is simulated in one process here."""
        deltas = {i: 0 for i in self.shares}
        for _dealer in range(self.n):
            coeffs = [0] + [secrets.randbelow(ORDER) for _ in range(self.k - 1)]
            for i in self.shares:
                deltas[i] = (deltas[i] + sum(c * pow(i, e, ORDER) for e, c in enumerate(coeffs))) % ORDER
        self.shares = {i: (sh + deltas[i]) % ORDER for i, sh in self.shares.items()}
        self.member_pks = {i: _G1_BASIS * ark.Scalar(sh) for i, sh in self.shares.items()}
        self.epoch = getattr(self, "epoch", 0) + 1

    def partial_sign(self, member_index: int, message: bytes):
        """Returns a raw G2 point (not yet a combined signature)."""
        M = ark.G2Point.hash_to_curve(message, DST_MESSAGE)
        return M * ark.Scalar(self.shares[member_index])

    def combine(self, partials: Dict[int, "ark.G2Point"]) -> bytes:
        """partials: {member_index: partial_sign(...) result} for >= k
        members. Returns the combined, verifiable compressed signature."""
        subset = list(partials.keys())
        if len(subset) < self.k:
            raise ValueError(f"need >= {self.k} shares, got {len(subset)}")
        subset = subset[: self.k]  # exactly k is enough; more is wasted work
        combined = None
        for i in subset:
            term = partials[i] * ark.Scalar(_lagrange_coeff(subset, i))
            combined = term if combined is None else combined + term
        return combined.to_compressed_bytes()

    def verify_partial(self, member_index: int, message: bytes, partial) -> bool:
        """Check one member's partial signature against that member's
        public key: e(basis, partial) == e(pk_i, H(m)). A faulty or
        malicious member that returns garbage is caught here, before it
        can poison the Lagrange combination."""
        M = ark.G2Point.hash_to_curve(message, DST_MESSAGE)
        return ark.GT.pairing_check([_G1_BASIS, -self.member_pks[member_index]], [partial, M])

    def combine_robust(self, message: bytes, partials: Dict[int, "ark.G2Point"]):
        """Fault-tolerant combine: verifies each received partial, drops
        invalid ones, and combines the first k valid ones. Returns
        (signature_bytes, rejected_member_indices). Raises ValueError if
        fewer than k valid partials remain (the liveness-failure case)."""
        valid, rejected = {}, []
        for i, part in partials.items():
            if self.verify_partial(i, message, part):
                valid[i] = part
            else:
                rejected.append(i)
        if len(valid) < self.k:
            raise ValueError(f"only {len(valid)} valid partials, need {self.k}")
        return self.combine(valid), rejected

    def sign_with_k_of_n(self, message: bytes, member_indices: Sequence[int] = None) -> bytes:
        """Convenience: compute k partials fresh and combine, in one call."""
        indices = list(member_indices) if member_indices else list(range(1, self.k + 1))
        partials = {i: self.partial_sign(i, message) for i in indices[: self.k]}
        return self.combine(partials)

    def verify(self, message: bytes, signature: bytes) -> bool:
        M = ark.G2Point.hash_to_curve(message, DST_MESSAGE)
        sig_point = ark.G2Point.from_compressed_bytes(signature)
        # e(basis, sig) == e(pk, M)  <=>  e(basis, sig) * e(-pk, M) == 1
        return ark.GT.pairing_check([_G1_BASIS, -self.pk], [sig_point, M])


def beacon_seed(committee: ThresholdBLSCommittee, message: bytes,
                 member_indices: Sequence[int] = None) -> int:
    """drand-style randomness beacon: seed = H(threshold signature).
    Unpredictable before k committee members sign, and verifiable by
    anyone holding the committee's public key -- replaces
    crypto_stub.vrf_seed's hash-of-strings stand-in with the real
    primitive it was standing in for."""
    sig = committee.sign_with_k_of_n(message, member_indices)
    return int.from_bytes(hashlib.sha256(sig).digest(), "big")


def self_test() -> bool:
    """Correctness check: any two distinct k-subsets reconstruct the
    identical signature, it verifies, and k-1 shares fail to verify.
    Returns True iff all checks pass -- run this before trusting any
    benchmark or seed produced by this module in a given environment."""
    committee = ThresholdBLSCommittee(k=3, n=5)
    msg = b"self-test-message"

    subset_a = {i: committee.partial_sign(i, msg) for i in [1, 2, 3]}
    subset_b = {i: committee.partial_sign(i, msg) for i in [3, 4, 5]}
    sig_a = committee.combine(subset_a)
    sig_b = committee.combine(subset_b)

    checks = [
        sig_a == sig_b,                                     # any k-subset reconstructs the same sig
        committee.verify(msg, sig_a),                        # and it's genuinely valid
        not committee.verify(b"different message", sig_a),   # doesn't verify against the wrong message
    ]

    short = {i: committee.partial_sign(i, msg) for i in [1, 2]}  # k-1 shares: should refuse
    try:
        committee.combine(short)
        checks.append(False)  # combine() should have raised ValueError, didn't
    except ValueError:
        checks.append(True)

    return all(checks)


def benchmark_sequential_latency_ms(k: int, n: int, n_trials: int = 20) -> float:
    """SEQUENTIAL upper bound: wall-clock time to produce all k partial
    signatures one after another on a single machine, then combine.
    Each member independently computing hash_to_curve(message) is
    realistic per-member work (they're separate parties, not sharing
    state) -- but running k of them back-to-back on one thread is NOT
    what a real distributed k-of-n committee's client-facing latency
    looks like, since real committee members sign in parallel. This
    number is a legitimate (if pessimistic) upper bound, not a latency
    estimate -- see benchmark_parallel_latency_ms for the realistic one.

    Reports the median, not the mean: at these sub-10ms magnitudes, OS
    scheduling jitter and GC pauses produce occasional outlier samples
    that skew a mean far more than they reflect typical latency -- the
    standard reason perf benchmarking reports percentiles, not averages."""
    committee = ThresholdBLSCommittee(k=k, n=n)
    durations = []
    for i in range(n_trials):
        msg = f"bench-message-{i}".encode()
        start = time.perf_counter()
        committee.sign_with_k_of_n(msg)
        durations.append((time.perf_counter() - start) * 1000.0)
    return statistics.median(durations)


def benchmark_parallel_latency_ms(k: int, n: int, n_trials: int = 20) -> float:
    """Realistic client-facing latency estimate for a properly deployed
    k-of-n committee: since members sign in parallel (separate
    machines), the client-facing cost is approximately ONE member's
    partial-sign time (the slowest of k concurrent, roughly equal-cost
    operations) plus the aggregator's combine step -- not k sequential
    repetitions of the former. Network round-trip time to collect shares
    is real and not modeled here (no actual network in this benchmark);
    this is a compute-only lower bound on real deployed latency, the
    complement of the sequential number being an upper bound on it.
    Reports the median for the same reason as benchmark_sequential_latency_ms."""
    committee = ThresholdBLSCommittee(k=k, n=n)
    durations = []
    for i in range(n_trials):
        msg = f"bench-message-{i}".encode()
        start = time.perf_counter()
        one_partial = committee.partial_sign(1, msg)  # representative of any single member, in parallel
        partials = {j: one_partial for j in range(1, k + 1)}  # stand-in: real members' partials differ,
        # but cost of producing each is what's being timed here, not the specific values combined
        committee.combine(partials)
        durations.append((time.perf_counter() - start) * 1000.0)
    return statistics.median(durations)
