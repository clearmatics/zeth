#!/usr/bin/env python3

# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
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
        sig_encoded = signing.signature_to_bytes(sig)
        sig_decoded = signing.signature_from_bytes(sig_encoded)
        self.assertEqual(sig, sig_decoded)

    def test_keypair_encode_decode(self) -> None:
        """
        Test encoding and decoding of key pair
        """
        keypair = signing.gen_signing_keypair()
        keypair_json = keypair.to_json_dict()
        keypair2 = signing.SigningKeyPair.from_json_dict(keypair_json)
        self.assertEqual(keypair_json, keypair2.to_json_dict())
