#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.joinsplit import EncryptionKeyPair, ZethAddress
from zeth.ownership import gen_ownership_keypair
from zeth.utils import get_private_key_from_bytes, get_public_key_from_bytes

from typing import Dict, List


KeyStore = Dict[str, ZethAddress]


def init_test_keystore() -> KeyStore:
    """
    Keystore for the tests
    """

    alice_25519_enc_private_key = \
        b'\xde\xa2\xc1\x0b\xd1\xf7\x13\xf8J\xa4:\xa4\xb6\xfa\xbd\xd5\xc9' + \
        b'\x8a\xd9\xb6\xb4\xc4\xc4I\x88\xa4\xd9\xe2\xee\x9e\x9a\xff'
    alice_25519_enc_public_key = \
        b'\x1eO"\n\xdaWnU+\xf5\xaa\x8a#\xd2*\xd3\x11\x9fc\xe52 \xd8^\xbc-' + \
        b'\xb6\xf1\xeej\xf41'

    bob_25519_enc_private_key = \
        b'\xd3\xf0\x8f ,\x1d#\xdc\xac,\x93\xbd\xd0\xd9\xed\x8c\x92\x822' + \
        b'\xef\xd6\x97^\x86\xf7\xe4/\x85\xb6\x10\xe6o'
    bob_25519_enc_public_key = \
        b't\xc5{5j\xb5\x8a\xd3n\xb3\xab9\xe8s^13\xba\xa2\x91x\xb01(\xf9' + \
        b'\xbb\xf9@r_\x91}'

    charlie_25519_enc_private_key = b'zH\xb66q\x97\x0bO\xcb\xb9q\x9b\xbd-1`I' + \
        b'\xae\x00-\x11\xb9\xed}\x18\x9f\xf6\x8dr\xaa\xd4R'
    charlie_25519_enc_public_key = \
        b'u\xe7\x88\x9c\xbfE(\xf8\x99\xca<\xa8[<\xa2\x88m\xad\rN"\xf0}' + \
        b'\xec\xfcB\x89\xe6\x96\xcf\x19U'

    # Alice credentials in the zeth abstraction
    alice_ownership = gen_ownership_keypair()
    alice_encryption = EncryptionKeyPair(
        get_private_key_from_bytes(alice_25519_enc_private_key),
        get_public_key_from_bytes(alice_25519_enc_public_key))

    # Bob credentials in the zeth abstraction
    bob_ownership = gen_ownership_keypair()
    bob_encryption = EncryptionKeyPair(
        get_private_key_from_bytes(bob_25519_enc_private_key),
        get_public_key_from_bytes(bob_25519_enc_public_key))

    # Charlie credentials in the zeth abstraction
    charlie_ownership = gen_ownership_keypair()
    charlie_encryption = EncryptionKeyPair(
        get_private_key_from_bytes(charlie_25519_enc_private_key),
        get_public_key_from_bytes(charlie_25519_enc_public_key))

    return {
        "Alice": ZethAddress.from_key_pairs(
            alice_ownership, alice_encryption),
        "Bob": ZethAddress.from_key_pairs(
            bob_ownership, bob_encryption),
        "Charlie": ZethAddress.from_key_pairs(
            charlie_ownership, charlie_encryption),
    }


def get_dummy_merkle_path(length: int) -> List[str]:
    mk_path = []
    # Arbitrary sha256 digest used to build the dummy merkle path
    dummy_node = \
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    for _ in range(length):
        mk_path.append(dummy_node)
    return mk_path
