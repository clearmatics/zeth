# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.constants import MIMC_MT_SEED
from zeth.core.merkle_tree import ITreeHash
from Crypto.Hash import keccak \
    # pylint: disable=import-error,no-name-in-module,line-too-long  #type: ignore
from abc import abstractmethod

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
#
# MiMC algorithms are exposed as ITreeHash objects for use in MerkleTree
# structures.


class MiMCBase(ITreeHash):
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

        # The round constant in round 0 is 0 (see [AGRRT16])
        result = self.mimc_round(result, key, 0)

        for _ in range(self.num_rounds - 1):
            round_constant = _update_round_constant(round_constant)
            result = self.mimc_round(result, key, round_constant)

        # Add key to the final result (see [AGRRT16])
        return (result + key) % self.prime

    def hash(self, left: bytes, right: bytes) -> bytes:
        """
        Apply Miyaguchi-Preneel to the output of the encrypt function.
        """
        x = int.from_bytes(left, byteorder='big') % self.prime
        y = int.from_bytes(right, byteorder='big') % self.prime
        result = (self.encrypt(x, y) + x + y) % self.prime
        return result.to_bytes(32, byteorder='big')

    @abstractmethod
    def mimc_round(self, message: int, key: int, rc: int) -> int:
        pass


class MiMC7(MiMCBase):
    """
    MiMC specialized for Fr in ALT-BN128, in which the exponent is 7 and 91
    rounds are used.
    """
    def __init__(self, seed_str: str = MIMC_MT_SEED):
        MiMCBase.__init__(
            self,
            seed_str,
            21888242871839275222246405745257275088548364400416034343698204186575808495617,  # noqa
            # pylint: disable=line-too-long
            91)

    def mimc_round(self, message: int, key: int, rc: int) -> int:
        xored = (message + key + rc) % self.prime
        return xored ** 7 % self.prime


class MiMC31(MiMCBase):
    """
    MiMC implementation using exponent of 31 and 51 rounds. Note that this is
    suitable for BLS12-377, since 31=2^5-1, and 1 == gcd(31, r-1). See
    [AGRRT16] for details.
    """
    def __init__(self, seed_str: str = MIMC_MT_SEED):
        MiMCBase.__init__(
            self,
            seed_str,
            8444461749428370424248824938781546531375899335154063827935233455917409239041,  # noqa
            51)

    def mimc_round(self, message: int, key: int, rc: int) -> int:
        a = (message + key + rc) % self.prime
        a_2 = (a * a) % self.prime
        a_4 = (a_2 * a_2) % self.prime
        a_8 = (a_4 * a_4) % self.prime
        a_16 = (a_8 * a_8) % self.prime
        return (a_16 * a_8 * a_4 * a_2 * a) % self.prime


def get_tree_hash_for_pairing(pairing_name: str) -> ITreeHash:
    """
    Select an appropriate hash for a given pairing. Note that these must match
    the selection logic in `libzeth/circuits/circuit_types.hpp`.
    """
    if pairing_name == "alt-bn128":
        return MiMC7()
    if pairing_name == "bls12-377":
        return MiMC31()
    raise Exception(f"no tree hash for pairing: {pairing_name}")


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
