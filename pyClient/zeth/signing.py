#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Implementation of Schnorr-based one-time signature from: "Two-tier
signatures, strongly unforgeable signatures, and Fiat-Shamir without random
oracles" by Bellare and Shoup (https://eprint.iacr.org/2007/273.pdf) over Curve
BN128
"""

from math import ceil
from os import urandom
from hashlib import sha256
from py_ecc import bn128 as ec
from zeth.utils import FQ, G1, g1_to_bytes
from zeth.constants import ZETH_PRIME
from typing import List


class SigningVerificationKey:
    """
    An OT-Schnorr verification key.
    """
    def __init__(self, x_g1: G1, y_g1: G1):
        self.ppk = x_g1
        self.spk = y_g1


class SigningSecretKey:
    """
    An OT-Schnorr signing key.
    """
    def __init__(self, x: FQ, y: FQ, y_g1: G1):
        self.psk = x
        self.ssk = (y, y_g1)


class SigningKeyPair:
    """
    An OT-Schnorr signing and verification keypair.
    """
    def __init__(self, x: FQ, y: FQ, x_g1: G1, y_g1: G1):
        # We include y_g1 in the signing key
        self.sk = SigningSecretKey(x, y, y_g1)
        self.vk = SigningVerificationKey(x_g1, y_g1)


Signature = int


def gen_signing_keypair() -> SigningKeyPair:
    """
    Return a one-time signature key-pair
    composed of elements of F_q and G1.
    """
    key_size_byte = ceil(len("{0:b}".format(ZETH_PRIME)) / 8)
    x = FQ(
        int(bytes(urandom(key_size_byte)).hex(), 16) % ZETH_PRIME)
    y = FQ(
        int(bytes(urandom(key_size_byte)).hex(), 16) % ZETH_PRIME)
    X = ec.multiply(ec.G1, x.n)
    Y = ec.multiply(ec.G1, y.n)
    return SigningKeyPair(x, y, X, Y)


def encode_vk_to_bytes(vk: SigningVerificationKey) -> bytes:
    """
    Encode a verification key as a byte string
    We assume here the group prime $p$ is written in less than 256 bits
    to conform with Ethereum bytes32 type
    """
    vk_byte = g1_to_bytes(vk.ppk)
    vk_byte += g1_to_bytes(vk.spk)
    return vk_byte


def encode_signature_to_bytes(signature: Signature) -> bytes:
    return signature.to_bytes(32, byteorder='big')


def decode_signature_from_bytes(sig_bytes: bytes) -> Signature:
    return int.from_bytes(sig_bytes, byteorder='big')


def sign(
        sk: SigningSecretKey,
        m: bytes) -> Signature:
    """
    Generate a Schnorr signature on a message m.
    We assume here that the message fits in an Ethereum word (i.e. bit_len(m)
    <= 256), so that it can be represented by a single bytes32 on the smart-
    contract during the signature verification.
    """

    # Encode and hash the verifying key and input hashes
    challenge_to_hash = g1_to_bytes(sk.ssk[1]) + m

    # Convert the hex digest into a field element
    challenge = int(sha256(challenge_to_hash).hexdigest(), 16)
    challenge = challenge % ZETH_PRIME

    # Compute the signature sigma
    sigma = (sk.ssk[0].n + challenge * sk.psk.n) % ZETH_PRIME

    return sigma


def verify(
        vk: SigningVerificationKey,
        m: bytes,
        sigma: int) -> bool:
    """
    Return true if the signature sigma is valid on message m and vk.
    We assume here that the message is an hexadecimal string written in
    less than 256 bits to conform with Ethereum bytes32 type.
    """
    # Encode and hash the verifying key and input hashes
    challenge_to_hash = g1_to_bytes(vk.spk) + m

    challenge = int(sha256(challenge_to_hash).hexdigest(), 16)
    challenge = challenge % ZETH_PRIME

    left_part = ec.multiply(ec.G1, FQ(sigma).n)
    right_part = ec.add(vk.spk, ec.multiply(vk.ppk, FQ(challenge).n))

    return ec.eq(left_part, right_part)


def verification_key_as_mix_parameter(vk: SigningVerificationKey) -> List[int]:
    """
    Transform a verification key to the format required by the mix function.
    """
    return [int(vk.ppk[0]), int(vk.ppk[1]), int(vk.spk[0]), int(vk.spk[1])]


def verification_key_from_mix_parameter(
        param: List[int]) -> SigningVerificationKey:
    """
    Transform mix function parameter to verification key.
    """
    return SigningVerificationKey(
        (FQ(param[0]), FQ(param[1])),
        (FQ(param[2]), FQ(param[3])))


def signature_as_mix_parameter(signature: Signature) -> int:
    """
    Transform a signature to the format required by the mix function.
    """
    # This function happens to be the identity but in the general case some
    # transform will be required.
    return signature


def signature_from_mix_parameter(param: int) -> Signature:
    """
    Transform mix function parameters to a signature.
    """
    return param
