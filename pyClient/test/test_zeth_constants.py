#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import zeth.encryption as encryption
from . import test_utils
from unittest import TestCase


class TestZethConstants(TestCase):

    def test_encrypt_decrypt(self) -> None:
        """
        Tests the correct encrypt-decrypt flow: decrypt(encrypt(m)) == m
        """
        message = "Join Clearmatics, we are hiring!"

        keypair_alice_bytes, keypair_bob_bytes, _ = test_utils.gen_keys_utility()

        pk_alice = encryption.decode_encryption_public_key(keypair_alice_bytes[0])
        sk_alice = encryption.decode_encryption_secret_key(keypair_alice_bytes[1])

        pk_bob = encryption.decode_encryption_public_key(keypair_bob_bytes[0])
        sk_bob = encryption.decode_encryption_secret_key(keypair_bob_bytes[1])

        # Subtest 1: Alice to Alice
        ciphertext_alice_alice = encryption.encrypt(message, pk_alice, sk_alice)
        plaintext_alice_alice = encryption.decrypt(
            ciphertext_alice_alice, pk_alice, sk_alice)
        self.assertEqual(plaintext_alice_alice, message)

        # Subest 2: Bob to Alice
        ciphertext_bob_alice = encryption.encrypt(message, pk_alice, sk_bob)
        plaintext_bob_alice = encryption.decrypt(
            ciphertext_bob_alice, pk_alice, sk_bob)
        self.assertEqual(plaintext_bob_alice, message)

        plaintext_bob_alice = encryption.decrypt(
            ciphertext_bob_alice, pk_bob, sk_alice)
        self.assertEqual(plaintext_bob_alice, message)
