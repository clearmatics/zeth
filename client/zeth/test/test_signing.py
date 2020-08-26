#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core import signing
from hashlib import sha256
from unittest import TestCase
from os import urandom


class TestSigning(TestCase):

    keypair = signing.gen_signing_keypair()

    def test_sign_verify(self) -> None:
        """
        Test the correct signing-verification flow:
        verify(vk, sign(sk,m), m) = 1
        """
        m = sha256("clearmatics".encode()).digest()
        sigma = signing.sign(self.keypair.sk, m)
        self.assertTrue(signing.verify(self.keypair.vk, m, sigma))

        keypair2 = signing.gen_signing_keypair()
        self.assertFalse(signing.verify(keypair2.vk, m, sigma))

    def test_sign_verify_random(self) -> None:
        """
        Test the correct signing-verification flow with random message:
        verify(vk, sign(sk,m), m) = 1
        """
        m = urandom(32)
        sigma = signing.sign(self.keypair.sk, m)
        self.assertTrue(signing.verify(self.keypair.vk, m, sigma))

        keypair2 = signing.gen_signing_keypair()
        self.assertFalse(signing.verify(keypair2.vk, m, sigma))

    def test_signature_encoding(self) -> None:
        """
        Test encoding and decoding of signatures.
        """
        m = sha256("clearmatics".encode()).digest()
        sig = signing.sign(self.keypair.sk, m)
        sig_encoded = signing.encode_signature_to_bytes(sig)
        sig_decoded = signing.decode_signature_from_bytes(sig_encoded)
        self.assertEqual(sig, sig_decoded)
