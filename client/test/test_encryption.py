#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import zeth.core.constants as constants
import zeth.core.encryption as encryption
from unittest import TestCase


_TEST_SECRET_KEY_BYTES = bytes.fromhex(
    "10c78d9b7cca67e76c528232ff6fb69c012ecf8dad6ce79dc43e42bc1a54de6c")
_TEST_SECRET_KEY_1_BYTES = bytes.fromhex(
    "10c78d9bc7ac767ec6252823fff66bc910e2fcd8dac67ed94ce324cba145ed6c")
_TEST_PLAINTEXT = ("T" * int(constants.NOTE_LENGTH / 8)).encode()


class TestEncryption(TestCase):

    def test_encrypt_decrypt(self) -> None:
        """
        Tests the correct encrypt-decrypt flow: decrypt(encrypt(m)) == m
        where m is encoded on NOTE_LENGTH/BYTE_LEN bytes.
        """
        sk = encryption.decode_encryption_secret_key(_TEST_SECRET_KEY_BYTES)
        pk = encryption.get_encryption_public_key(sk)
        ciphertext = encryption.encrypt(_TEST_PLAINTEXT, pk)
        plaintext = encryption.decrypt(ciphertext, sk)
        self.assertEqual(_TEST_PLAINTEXT, plaintext)

    def test_decryption_invalid_key(self) -> None:
        """
        Tests that ONLY the owner of the receiver key can decrypt the ciphertext.
        """
        sk_1 = encryption.decode_encryption_secret_key(_TEST_SECRET_KEY_1_BYTES)
        sk = encryption.decode_encryption_secret_key(_TEST_SECRET_KEY_BYTES)
        pk = encryption.get_encryption_public_key(sk)
        ciphertext = encryption.encrypt(_TEST_PLAINTEXT, pk)
        with self.assertRaises(encryption.InvalidSignature):
            encryption.decrypt(ciphertext, sk_1)

    def test_private_key_generation(self) -> None:
        """
        Sample some random keys and ensure that they comply with the
        specification. See encryption.py for details.
        """
        for _ in range(128):
            sk = encryption.generate_encryption_secret_key()
            sk_bytes = encryption.encode_encryption_secret_key(sk)
            # print(f"key:{sk_bytes.hex()}")

            sk_first_byte = int(sk_bytes[0])
            sk_last_byte = int(sk_bytes[31])
            self.assertEqual(
                0,
                sk_first_byte % 8,
                "invalid key data (first byte not multiple of 8)")
            self.assertTrue(
                64 <= sk_last_byte <= 127,
                f"invalid key data (invalid last byte: {sk_last_byte})")
