"""Closes threat-model gap A4 (THREAT-MODEL.md §2): "racing the
post-decryption dispatch." The original design only point-to-point
addressed the reveal to the winner, which is not the same as
*authenticating* it -- a network-level racer (A2/A4) who simply
responds faster than the real winner on the same channel could still
grab the plaintext query before the real winner does. Point-to-point
routing alone doesn't stop that; encrypting the reveal payload so only
the winner's registered key can open it does.

This module gives every bonded provider identity (THREAT-MODEL.md §4.1)
a standard X25519 keypair at registration time, and implements a
sealed-box (ECIES-style: ephemeral X25519 ECDH + HKDF + ChaCha20Poly1305
AEAD) construction so the committee's Reveal step (§4 point 4) can
encrypt the query specifically to the winning provider's *public* key.
A racer who wins the network race but does not hold the winner's
private key receives ciphertext it cannot open -- A4 degenerates to
"break a standard AEAD scheme," a solved problem out of this protocol's
novelty claim, exactly as THREAT-MODEL.md originally asserted without
actually enforcing it. This module is what makes that assertion true
instead of aspirational.

Built on `cryptography` (already a project dependency elsewhere via
pip), not on the BLS/pairing stack in threshold_bls.py -- point-to-point
authenticated encryption is a different primitive than threshold
signatures, and forcing it through pairing curves would be the wrong
tool for the job.

Deployment note: in a real system only the public key travels through
the registry; the private key never leaves the provider's own
infrastructure. This module holds both sides only because the
simulation plays every party itself -- see self_test() and exp8's A4
demonstration for where that matters.
"""
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidTag

_NONCE_LEN = 12
_PUBKEY_LEN = 32


@dataclass
class ProviderIdentity:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey

    @property
    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def generate_identity() -> ProviderIdentity:
    """One-time keypair generation at bonding (THREAT-MODEL.md §4.1
    point 1) -- amortized once, like the stake itself, not per task."""
    sk = X25519PrivateKey.generate()
    return ProviderIdentity(private_key=sk, public_key=sk.public_key())


def _derive_aead_key(shared_secret: bytes, ephemeral_pub_bytes: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"sealed-dispatch-reveal-v1" + ephemeral_pub_bytes,
    ).derive(shared_secret)


def seal_for_provider(plaintext: bytes, recipient_public_key: X25519PublicKey) -> bytes:
    """Committee's Reveal step: encrypt `plaintext` (the task query) so
    only the holder of `recipient_public_key`'s matching private key can
    read it. Returns ephemeral_pubkey || nonce || ciphertext, safe to
    send over an otherwise-unauthenticated channel -- an A4 racer who
    intercepts this blob gains nothing without the recipient's private key."""
    ephemeral_sk = X25519PrivateKey.generate()
    ephemeral_pub_bytes = ephemeral_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    shared_secret = ephemeral_sk.exchange(recipient_public_key)
    aead_key = _derive_aead_key(shared_secret, ephemeral_pub_bytes)

    nonce = os.urandom(_NONCE_LEN)
    ciphertext = ChaCha20Poly1305(aead_key).encrypt(nonce, plaintext, associated_data=None)

    return ephemeral_pub_bytes + nonce + ciphertext


def open_sealed(blob: bytes, recipient_private_key: X25519PrivateKey) -> bytes:
    """Winner's side: recover the plaintext. Raises `InvalidTag` (from
    `cryptography`) if `recipient_private_key` does not match the key
    the blob was sealed for -- this is the failure exp8 exercises to
    demonstrate A4 closure: an intercepting racer holding a different
    keypair gets this exception, not the plaintext."""
    ephemeral_pub_bytes = blob[:_PUBKEY_LEN]
    nonce = blob[_PUBKEY_LEN:_PUBKEY_LEN + _NONCE_LEN]
    ciphertext = blob[_PUBKEY_LEN + _NONCE_LEN:]

    ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    shared_secret = recipient_private_key.exchange(ephemeral_pub)
    aead_key = _derive_aead_key(shared_secret, ephemeral_pub_bytes)

    return ChaCha20Poly1305(aead_key).decrypt(nonce, ciphertext, associated_data=None)


def self_test() -> bool:
    """Correctness + the actual security property exp8 relies on: the
    intended recipient opens successfully; a different keypair (modeling
    an A4 racer who won the network race but isn't the real winner)
    fails with InvalidTag, not with the plaintext."""
    winner = generate_identity()
    racer = generate_identity()  # A4: wins the race, doesn't hold winner's key

    plaintext = b"task query: translate this document, budget $50"
    sealed = seal_for_provider(plaintext, winner.public_key)

    checks = []
    try:
        recovered = open_sealed(sealed, winner.private_key)
        checks.append(recovered == plaintext)
    except InvalidTag:
        checks.append(False)  # the real winner should NOT fail to open its own reveal

    try:
        open_sealed(sealed, racer.private_key)
        checks.append(False)  # the racer should NOT be able to open it
    except InvalidTag:
        checks.append(True)  # correctly denied

    return all(checks)
