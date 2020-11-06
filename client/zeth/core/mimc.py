# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.constants import MIMC_MT_SEED
from Crypto.Hash import keccak \
    # pylint: disable=import-error,no-name-in-module,line-too-long  #type: ignore
from abc import (ABC, abstractmethod)

# Reference papers:
#
# \[AGRRT16]:
# "MiMC: Efficient Encryption and Cryptographic Hashing with Minimal
# Multiplicative Complexity", Martin Albrecht, Lorenzo Grassi, Christian
# Rechberger, Arnab Roy, and Tyge Tiessen, ASIACRYPT 2016,
# <https://eprint.iacr.org/2016/492.pdf>
#
# "One-way compression function"
# Section: "Miyaguchi–Preneel"
# <https://en.wikipedia.org/wiki/One-way_compression_function#Miyaguchi%E2%80%93Preneel>


class MiMCBase(ABC):
    """
    Base class of MiMC implmentations.
    """
    def __init__(
            self,
            seed_str: str,
            prime: int,
            num_rounds: int):
        self.seed = _keccak_256(_str_to_bytes(seed_str))
        self.prime = prime
        self.num_rounds = num_rounds

    def encrypt(
            self,
            message: int,
            ek: int) -> int:
        result = message % self.prime
        key = ek % self.prime
        round_constant: int = self.seed

        # The rc in round 0 is 0 (see [AGRRT16])
        result = self.mimc_round(result, key, 0)

        for _ in range(self.num_rounds - 1):
            round_constant = _update_round_constant(round_constant)
            result = self.mimc_round(result, key, round_constant)

        # Add key to the final result (see [AGRRT16])
        return (result + key) % self.prime

    def hash(self, x: int, y: int) -> int:
        """
        Apply Miyaguchi-Preneel to the output of the encrypt function.
        """
        x = x % self.prime
        y = y % self.prime
        return (self.encrypt(x, y) + x + y) % self.prime

    @abstractmethod
    def mimc_round(self, message: int, key: int, rc: int) -> int:
        pass


class MiMC7(MiMCBase):
    """
    MiMC specialized for Fr in ALT-BN128, in which the exponent is 7 and 91
    rounds are used.
    """
    def __init__(
            self,
            seed_str: str = MIMC_MT_SEED):
        MiMCBase.__init__(
            self,
            seed_str,
            21888242871839275222246405745257275088548364400416034343698204186575808495617,  # noqa
            # pylint: disable=line-too-long
            91)

    def mimc_round(self, message: int, key: int, rc: int) -> int:
        # a = (message + key + rc) % self.prime
        # a2 = (a * a) % self.prime
        # a4 = (a2 * a2) % self.prime
        # a6 = (a4 * a2) % self.prime
        # return (a * a6) % self.prime
        # return ((((a2 * a2) % self.prime) * a2 % prime) * a) % self.prime
        xored = (message + key + rc) % self.prime
        return xored ** 7 % self.prime


class MiMC31(MiMCBase):
    """
    MiMC implementation using exponent of 11 and 51 rounds. Note that this is
    suitable for BLS12-377, since 31=2^5-1, and 1 == gcd(31, r-1). See
    [AGRRT16] for details.
    """
    def __init__(
            self,
            seed_str: str = MIMC_MT_SEED):
        MiMCBase.__init__(
            self,
            seed_str,
            8444461749428370424248824938781546531375899335154063827935233455917409239041,  # noqa
            51)

    def mimc_round(self, message: int, key: int, rc: int) -> int:
        a = (message + key + rc) % self.prime
        a2 = (a * a) % self.prime
        a4 = (a2 * a2) % self.prime
        a8 = (a4 * a4) % self.prime
        a16 = (a8 * a8) % self.prime
        return (a16 * a8 * a4 * a2 * a) % self.prime


def _str_to_bytes(value: str) -> bytes:
    return value.encode('ascii')


def _int_to_bytes32(value: int) -> bytes:
    return value.to_bytes(32, 'big')


def _keccak_256(data_bytes: bytes) -> int:
    h = keccak.new(digest_bits=256)
    h.update(data_bytes)
    hashed = h.digest()
    return int.from_bytes(hashed, 'big')


def _update_round_constant(rc: int) -> int:
    return _keccak_256(_int_to_bytes32(rc))
