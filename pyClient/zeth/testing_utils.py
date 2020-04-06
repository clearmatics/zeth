#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.encryption import generate_encryption_secret_key,\
    encode_encryption_secret_key, get_encryption_public_key,\
    encode_encryption_public_key

from typing import Tuple, List
from zeth.mimc import MiMC7


def gen_keys_utility(
        to_print: bool = False) -> Tuple[List[bytes], List[bytes], List[bytes]]:
    """
    Generates private/public keys (kP, k) over Curve25519 for Alice, Bob and
    Charlie
    """

    # Alice
    sk_alice = generate_encryption_secret_key()
    sk_alice_bytes = encode_encryption_secret_key(sk_alice)
    pk_alice = get_encryption_public_key(sk_alice)
    pk_alice_bytes = encode_encryption_public_key(pk_alice)

    alice_keys_bytes = [pk_alice_bytes, sk_alice_bytes]

    # Bob
    sk_bob = generate_encryption_secret_key()
    sk_bob_bytes = encode_encryption_secret_key(sk_bob)
    pk_bob = get_encryption_public_key(sk_bob)
    pk_bob_bytes = encode_encryption_public_key(pk_bob)

    bob_keys_bytes = [pk_bob_bytes, sk_bob_bytes]

    # Charlie
    sk_charlie = generate_encryption_secret_key()
    sk_charlie_bytes = encode_encryption_secret_key(sk_charlie)
    pk_charlie = get_encryption_public_key(sk_charlie)
    pk_charlie_bytes = encode_encryption_public_key(pk_charlie)

    charlie_keys_bytes = [pk_charlie_bytes, sk_charlie_bytes]

    if to_print:
        print("Alice")
        print(pk_alice_bytes)
        print(sk_alice_bytes)

        print("Bob")
        print(pk_bob_bytes)
        print(sk_bob_bytes)

        print("Charlie")
        print(pk_charlie_bytes)
        print(sk_charlie_bytes)

    return alice_keys_bytes, bob_keys_bytes, charlie_keys_bytes


def mimc_encrypt_utility() -> None:
    """
    Generates test vector for MiMC encrypt
    """
    m = MiMC7()
    msg = 3703141493535563179657531719960160174296085208671919316200479060314459804651  # noqa
    ek = \
        15683951496311901749339509118960676303290224812129752890706581988986633412003  # noqa
    ct = m.mimc_encrypt(msg, ek)
    print("MiMC encrypt test vector:")
    print(f"msg = {msg}")
    print(f"ek  = {ek}")
    print(f"ct  = {ct}\n")


def mimc_mp_utility() -> None:
    """
    Generates test vector for MiMC Hash
    """
    m = MiMC7()
    x = 3703141493535563179657531719960160174296085208671919316200479060314459804651  # noqa
    y = 15683951496311901749339509118960676303290224812129752890706581988986633412003  # noqa

    digest = m.mimc_mp(x, y)
    print("MiMC MP test vector:")
    print(f"x      = {x}")
    print(f"y      = {y}")
    print(f"digest = {digest}\n")


def mimc_tree_utility() -> None:
    """
    # Generates test vectors for testing the MiMC Merkle Tree contract.  A
    # 16 entry (4 level) merkle tree with 0 values everywhere.
    """
    m = MiMC7()
    level_3 = m.mimc_mp(0, 0)
    level_2 = m.mimc_mp(level_3, level_3)
    level_1 = m.mimc_mp(level_2, level_2)
    root = m.mimc_mp(level_1, level_1)

    print("MiMC Tree test vector (4 entries, all zero):")

    print(f"Level 2 = {level_3}")
    print(f"Level 2 = {level_2}")
    print(f"Level 1 = {level_1}")
    print(f"Root    = {root}\n")
