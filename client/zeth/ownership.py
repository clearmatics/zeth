#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations

from zeth.utils import hex_extend_32bytes, digest_to_binary_string, encode_abi

from Crypto import Random
from hashlib import blake2s
from typing import NewType


# Secret key for proving ownership
OwnershipSecretKey = NewType('OwnershipSecretKey', bytes)


# Public key for proving owenership
OwnershipPublicKey = NewType('OwnershipPublicKey', bytes)


class OwnershipKeyPair:
    """
    Key-pair for ownership proof
    """
    def __init__(self, a_sk: OwnershipSecretKey, a_pk: OwnershipPublicKey):
        self.a_sk: OwnershipSecretKey = a_sk
        self.a_pk: OwnershipPublicKey = a_pk


def ownership_key_as_hex(a_sk: bytes) -> str:
    """
    Convert either a secret or public ownership key to hex representation of the
    underlying 32-byte object.
    """
    return hex_extend_32bytes(a_sk.hex())


def ownership_public_key_from_hex(key_hex: str) -> OwnershipPublicKey:
    """
    Read an ownership public key from a hex string.
    """
    return OwnershipPublicKey(bytes.fromhex(key_hex))


def ownership_secret_key_from_hex(key_hex: str) -> OwnershipSecretKey:
    """
    Read an ownership public key from a hex string.
    """
    return OwnershipSecretKey(bytes.fromhex(key_hex))


def gen_ownership_keypair() -> OwnershipKeyPair:
    a_sk = OwnershipSecretKey(Random.get_random_bytes(32))
    a_pk = _derive_a_pk(a_sk)
    keypair = OwnershipKeyPair(a_sk, a_pk)
    return keypair


def _derive_a_pk(a_sk: OwnershipSecretKey) -> OwnershipPublicKey:
    """
    Returns a_pk = blake2s(1100 || [a_sk]_252 || 0^256)
    """
    binary_a_sk = digest_to_binary_string(a_sk)
    first_252bits_ask = binary_a_sk[:252]
    left_leg_bin = "1100" + first_252bits_ask
    left_leg_hex = "{0:0>4X}".format(int(left_leg_bin, 2))
    zeroes = "0000000000000000000000000000000000000000000000000000000000000000"
    a_pk = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            [bytes.fromhex(left_leg_hex), bytes.fromhex(zeroes)])
    ).digest()
    return OwnershipPublicKey(a_pk)
