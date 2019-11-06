import zeth.utils
from . import test_utils
from unittest import TestCase


class TestZethConstants(TestCase):

    def test_encrypt_decrypt(self):
        """
        Tests the correct encrypt-decrypt flow: decrypt(encrypt(m)) == m
        """
        message = "Join Clearmatics, we are hiring!"

        keypair_alice_bytes, keypair_bob_bytes, _ = test_utils.gen_keys_utility()

        pk_alice = zeth.utils.get_public_key_from_bytes(keypair_alice_bytes[0])
        sk_alice = zeth.utils.get_private_key_from_bytes(keypair_alice_bytes[1])

        pk_bob = zeth.utils.get_public_key_from_bytes(keypair_bob_bytes[0])
        sk_bob = zeth.utils.get_private_key_from_bytes(keypair_bob_bytes[1])

        # Subtest 1: Alice to Alice
        ciphertext_alice_alice = zeth.utils.encrypt(message, pk_alice, sk_alice)
        plaintext_alice_alice = zeth.utils.decrypt(
            ciphertext_alice_alice, pk_alice, sk_alice)
        self.assertEqual(plaintext_alice_alice, message)

        # Subest 2: Bob to Alice
        ciphertext_bob_alice = zeth.utils.encrypt(message, pk_alice, sk_bob)
        plaintext_bob_alice = zeth.utils.decrypt(
            ciphertext_bob_alice, pk_alice, sk_bob)
        self.assertEqual(plaintext_bob_alice, message)

        plaintext_bob_alice = zeth.utils.decrypt(
            ciphertext_bob_alice, pk_bob, sk_alice)
        self.assertEqual(plaintext_bob_alice, message)
