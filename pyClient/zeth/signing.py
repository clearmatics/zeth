"""
Types and basic operations for signing joinsplit data.
"""

import zeth.constants as constants
from py_ecc import bn128 as ec
from Crypto import Random
from typing import Tuple, NewType


FQ = ec.FQ
G1 = Tuple[ec.FQ, ec.FQ]


# Secret key for signing joinsplit data
SigningSecretKey = NewType('SigningSecretKey', Tuple[FQ, FQ])


# Public key for signing joinsplit data
SigningPublicKey = NewType('SigningPublicKey', Tuple[G1, G1])


class SigningKeyPair:
    """
    Key-pair for signing joinsplit data.
    """
    def __init__(self, sk: SigningSecretKey, pk: SigningPublicKey):
        self.sk: SigningSecretKey = sk
        self.pk: SigningPublicKey = pk


def gen_signing_keypair() -> SigningKeyPair:
    x = FQ(
        int(bytes(Random.get_random_bytes(32)).hex(), 16) % constants.ZETH_PRIME)
    X = ec.multiply(ec.G1, x.n)
    y = FQ(
        int(bytes(Random.get_random_bytes(32)).hex(), 16) % constants.ZETH_PRIME)
    Y = ec.multiply(ec.G1, y.n)
    return SigningKeyPair(SigningSecretKey((x, y)), SigningPublicKey((X, Y)))
