from math import ceil
from os import urandom
from typing import Tuple
from hashlib import sha256
from py_ecc import bn128 as ec

from zeth.utils import encode_g1_to_bytes
import zeth.constants as constants

FQ = ec.FQ
G1 = Tuple[ec.FQ, ec.FQ]

"""
This package implements the Schnorr based one-time signature from:
"Two-tier signatures, strongly unforgeable signatures,
and Fiat-Shamir without random oracles" by Bellare and Shoup
(https://eprint.iacr.org/2007/273.pdf) over Curve BN128
"""


class SchnorrVerificationKey:
    """
    An OT-Schnorr verification key.
    """
    def __init__(self, x_g1: G1, y_g1: G1):
        self.ppk = x_g1
        self.spk = y_g1


class SchnorrSigningKey:
    """
    An OT-Schnorr signing key.
    """
    def __init__(self, x: FQ, y: FQ, y_g1: G1):
        self.psk = x
        self.ssk = (y, y_g1)


class SchnorrKeyPair:
    """
    An OT-Schnorr signing and verification keypair.
    """
    def __init__(self, x: FQ, y: FQ, x_g1: G1, y_g1: G1):
        # We include in the signing key the verfication key
        self.sk = SchnorrSigningKey(x, y, y_g1)
        self.vk = SchnorrVerificationKey(x_g1, y_g1)


def key_gen() -> SchnorrKeyPair:
    """
    Return a one-time signature key-pair
    composed of elements of F_q and G1.
    """
    key_size_byte = ceil(len("{0:b}".format(constants.ZETH_PRIME)) / 8)
    x = FQ(
        int(bytes(urandom(key_size_byte)).hex(), 16) % constants.ZETH_PRIME)
    y = FQ(
        int(bytes(urandom(key_size_byte)).hex(), 16) % constants.ZETH_PRIME)
    X = ec.multiply(ec.G1, x.n)
    Y = ec.multiply(ec.G1, y.n)
    return SchnorrKeyPair(x, y, X, Y)


def gen_vk(sk: SchnorrSigningKey) -> SchnorrVerificationKey:
    """
    Generate an OT-Schnorr verification key from an OT-Schnorr signing key
    """
    x = sk.psk
    y, _ = sk.ssk
    X = ec.multiply(ec.G1, x.n)
    Y = ec.multiply(ec.G1, y.n)
    return SchnorrVerificationKey(X, Y)


def encode_vk_to_bytes(vk: SchnorrVerificationKey) -> bytes:
    """
    Encode a verification key as a byte string
    We assume here the group prime $p$ is written in less than 256 bits
    to conform with Ethereum bytes32 type
    """
    vk_byte = encode_g1_to_bytes(vk.ppk)
    vk_byte += encode_g1_to_bytes(vk.spk)
    return vk_byte


def sign(
        sk: SchnorrSigningKey,
        m: bytes) -> int:
    """
    Generate a Schnorr signature on a message m.
    We assume here that the message fits in an Ethereum word (i.e. bit_len(m)
    <= 256), so that it can be represented by a single bytes32 on the smart-
    contract during the signature verification.
    """

    # Encode and hash the verifying key and input hashes
    challenge_to_hash = encode_g1_to_bytes(sk.ssk[1]) + m

    # Convert the hex digest into a field element
    challenge = int(sha256(challenge_to_hash).hexdigest(), 16)
    challenge = challenge % constants.ZETH_PRIME

    # Compute the signature sigma
    sigma = (sk.ssk[0].n + challenge * sk.psk.n) % constants.ZETH_PRIME

    return sigma


def verify(
        vk: SchnorrVerificationKey,
        m: bytes,
        sigma: int) -> bool:
    """
    Return true if the signature sigma is valid on message m and vk.
    We assume here that the message is an hexadecimal string written in
    less than 256 bits to conform with Ethereum bytes32 type.
    """
    # Encode and hash the verifying key and input hashes
    challenge_to_hash = encode_g1_to_bytes(vk.spk) + m

    challenge = int(sha256(challenge_to_hash).hexdigest(), 16)
    challenge = challenge % constants.ZETH_PRIME

    left_part = ec.multiply(ec.G1, FQ(sigma).n)
    right_part = ec.add(vk.spk, ec.multiply(vk.ppk, FQ(challenge).n))

    return ec.eq(left_part, right_part)
