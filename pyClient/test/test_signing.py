from zeth import signing
from hashlib import sha256
from unittest import TestCase
from os import urandom


class TestSigning(TestCase):

    def test_sign_verify(self) -> None:
        """
        Test the correct signing-verification flow:
        verify(vk, sign(sk,m), m) = 1
        """
        m = sha256("clearmatics".encode()).digest()
        keypair = signing.gen_signing_keypair()
        sigma = signing.sign(keypair.sk, m)
        self.assertTrue(signing.verify(keypair.vk, m, sigma))

        keypair2 = signing.gen_signing_keypair()
        self.assertFalse(signing.verify(keypair2.vk, m, sigma))

    def test_sign_verify_random(self) -> None:
        """
        Test the correct signing-verification flow with random message:
        verify(vk, sign(sk,m), m) = 1
        """
        m = urandom(32)
        keypair = signing.gen_signing_keypair()
        sigma = signing.sign(keypair.sk, m)
        self.assertTrue(signing.verify(keypair.vk, m, sigma))

        keypair2 = signing.gen_signing_keypair()
        self.assertFalse(signing.verify(keypair2.vk, m, sigma))
