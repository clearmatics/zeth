# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.constants import ZETH_PRIME, MIMC_MT_SEED
from Crypto.Hash import keccak \
    # pylint: disable=import-error,no-name-in-module,line-too-long  #type: ignore
from typing import Optional


class MiMC7:
    """
    Python implementation of MiMC7 algorithm used in the mixer contract
    """

    def __init__(
            self,
            seed: str = MIMC_MT_SEED,
            prime: int = ZETH_PRIME):
        self.prime = prime
        self.seed = seed

    def mimc_round(self, message: int, key: int, rc: int) -> int:
        xored = (message + key + rc) % self.prime
        return xored ** 7 % self.prime

    def mimc_encrypt(
            self,
            message: int,
            ek: int,
            seed: Optional[str] = None,
            rounds: int = 91) -> int:
        seed = seed or self.seed
        res = message % self.prime
        key = ek % self.prime

        # In the paper the first round constant is set to 0
        res = self.mimc_round(res, key, 0)

        round_constant: int = _keccak_256(_str_to_bytes(seed))

        for _ in range(rounds - 1):
            round_constant = _keccak_256(_int_to_bytes32(round_constant))
            res = self.mimc_round(res, key, round_constant)

        return (res + key) % self.prime

    def mimc_mp(self, x: int, y: int) -> int:
        x = x % self.prime
        y = y % self.prime
        return (self.mimc_encrypt(x, y, self.seed) + x + y) % self.prime


def _str_to_bytes(value: str) -> bytes:
    return value.encode('ascii')


def _int_to_bytes32(value: int) -> bytes:
    return value.to_bytes(32, 'big')


def _keccak_256(data_bytes: bytes) -> int:
    h = keccak.new(digest_bits=256)
    h.update(data_bytes)
    hashed = h.digest()
    return int.from_bytes(hashed, 'big')
