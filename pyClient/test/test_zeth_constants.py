#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import zeth.encryption as encryption
from zeth import testing_utils
from zeth.utils import bits_to_bytes_len
from unittest import TestCase
from secrets import token_bytes
from zeth.constants import APK_LENGTH, NOTE_VALUE_LENGTH,\
    RHO_LENGTH, TRAPR_LENGTH


class TestZethConstants(TestCase):

    def test_encrypt_decrypt(self) -> None:
        """
        Tests the correct encrypt-decrypt flow: decrypt(encrypt(m)) == m
        where m is encoded on NOTE_LENGTH/BYTE_LEN bytes.
        """
        apk = token_bytes(bits_to_bytes_len(APK_LENGTH))
        value = token_bytes(bits_to_bytes_len(NOTE_VALUE_LENGTH))
        rho = token_bytes(bits_to_bytes_len(RHO_LENGTH))
        trap_r = token_bytes(bits_to_bytes_len(TRAPR_LENGTH))
        message = (apk + value + rho + trap_r)
        keypair_alice_bytes, _, _ = testing_utils.\
            gen_keys_utility()

        pk_alice = encryption.\
            get_public_key_from_bytes(keypair_alice_bytes[0])
        sk_alice = encryption.\
            get_private_key_from_bytes(keypair_alice_bytes[1])

        # Subtest 1: Alice to Alice
        ciphertext_alice_alice = encryption.\
            encrypt(message, pk_alice)
        plaintext_alice_alice = encryption.decrypt(
            ciphertext_alice_alice, sk_alice)
        self.assertEqual(plaintext_alice_alice, message)

        # Subest 2: Bob to Alice
        ciphertext_bob_alice = encryption.encrypt(message, pk_alice)
        plaintext_bob_alice = encryption.decrypt(
            ciphertext_bob_alice, sk_alice)
        self.assertEqual(plaintext_bob_alice, message)
