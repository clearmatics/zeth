#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Implementation of Schnorr-based one-time signature from: "Two-tier
signatures, strongly unforgeable signatures, and Fiat-Shamir without random
oracles" by Bellare and Shoup (https://eprint.iacr.org/2007/273.pdf) over Curve
BN128
"""

from __future__ import annotations
from math import ceil
from os import urandom
from hashlib import sha256
from py_ecc import bn128 as ec
from typing import Dict, List, Tuple, Any

FQ = ec.FQ
G1 = Tuple[ec.FQ, ec.FQ]


class SigningVerificationKey:
    """
    An OT-Schnorr verification key.
    """
    def __init__(self, ppk: G1, spk: G1):
        self.ppk = ppk
        self.spk = spk

    def to_bytes(self) -> bytes:
        return g1_to_bytes(self.ppk) + g1_to_bytes(self.spk)

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "ppk": g1_to_json_dict(self.ppk),
            "spk": g1_to_json_dict(self.spk),
        }

    @staticmethod
    def from_json_dict(json_dict: Dict[str, Any]) -> SigningVerificationKey:
        return SigningVerificationKey(
            ppk=g1_from_json_dict(json_dict["ppk"]),
            spk=g1_from_json_dict(json_dict["spk"]))


class SigningSecretKey:
    """
    An OT-Schnorr signing key.
    """
    def __init__(self, x: FQ, y: FQ, y_g1: G1):
        self.psk = x
        self.ssk = (y, y_g1)

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "psk": fq_to_hex(self.psk),
            "ssk_y": fq_to_hex(self.ssk[0]),
            "ssk_y_g1": g1_to_json_dict(self.ssk[1]),
        }

    @staticmethod
    def from_json_dict(json_dict: Dict[str, Any]) -> SigningSecretKey:
        return SigningSecretKey(
            x=fq_from_hex(json_dict["psk"]),
            y=fq_from_hex(json_dict["ssk_y"]),
            y_g1=g1_from_json_dict(json_dict["ssk_y_g1"]))


class SigningKeyPair:
    """
    An OT-Schnorr signing and verification keypair.
    """
    def __init__(self, sk: SigningSecretKey, vk: SigningVerificationKey):
        self.sk = sk
        self.vk = vk

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "sk": self.sk.to_json_dict(),
            "vk": self.vk.to_json_dict(),
        }

    @staticmethod
    def from_json_dict(json_dict: Dict[str, Any]) -> SigningKeyPair:
        return SigningKeyPair(
            SigningSecretKey.from_json_dict(json_dict["sk"]),
            SigningVerificationKey.from_json_dict(json_dict["vk"]))


def gen_signing_keypair() -> SigningKeyPair:
    """
    Return a one-time signature key-pair
    composed of elements of F_q and G1.
    """
    key_size_byte = ceil(len("{0:b}".format(ec.curve_order)) / 8)
    x = FQ(
        int(bytes(urandom(key_size_byte)).hex(), 16) % ec.curve_order)
    y = FQ(
        int(bytes(urandom(key_size_byte)).hex(), 16) % ec.curve_order)
    X = ec.multiply(ec.G1, x.n)
    Y = ec.multiply(ec.G1, y.n)

    # We include y_g1 in the signing key
    sk = SigningSecretKey(x, y, Y)
    vk = SigningVerificationKey(X, Y)
    return SigningKeyPair(sk, vk)


Signature = int


def signature_to_bytes(signature: Signature) -> bytes:
    return signature.to_bytes(32, byteorder='big')


def signature_from_bytes(sig_bytes: bytes) -> Signature:
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
    challenge = challenge % ec.curve_order

    # Compute the signature sigma
    sigma = (sk.ssk[0].n + challenge * sk.psk.n) % ec.curve_order
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
    challenge = challenge % ec.curve_order

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

# Low level encoding / decoding functions


def fq_to_bytes(fq_element: FQ) -> bytes:
    return int(fq_element.n).to_bytes(32, byteorder='big')


def fq_from_bytes(fq_bytes: bytes) -> FQ:
    return FQ(int.from_bytes(fq_bytes, byteorder='big'))


def fq_to_hex(fq_element: FQ) -> str:
    return fq_to_bytes(fq_element).hex()


def fq_from_hex(fq_hex: str) -> FQ:
    return fq_from_bytes(bytes.fromhex(fq_hex))


def g1_to_bytes(group_el: G1) -> bytes:
    """
    Encode a group element into a byte string
    We assume here the group prime $p$ is written in less than 256 bits
    to conform with Ethereum bytes32 type.
    """
    return \
        int(group_el[0]).to_bytes(32, byteorder='big') + \
        int(group_el[1]).to_bytes(32, byteorder='big')


def g1_to_json_dict(group_el: G1) -> Dict[str, Any]:
    return {
        "x": fq_to_hex(group_el[0]),
        "y": fq_to_hex(group_el[1]),
    }


def g1_from_json_dict(json_dict: Dict[str, Any]) -> G1:
    return (fq_from_hex(json_dict["x"]), fq_from_hex(json_dict["y"]))
