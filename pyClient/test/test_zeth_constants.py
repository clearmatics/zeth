import zethUtils

from nacl.public import PrivateKey, PublicKey

# Tests the correct encrypt-decrypt flow: decrypt(encrypt(m)) == m
def test_encrypt_decrypt():
  message = "Join Clearmatics, we are hiring!"

  keypair_alice_bytes, keypair_bob_bytes, _ = zethUtils.gen_keys_utility()

  pk_alice = zethUtils.get_public_key_from_bytes(keypair_alice_bytes[0])
  sk_alice = zethUtils.get_private_key_from_bytes(keypair_alice_bytes[1])

  pk_bob = zethUtils.get_public_key_from_bytes(keypair_bob_bytes[0])
  sk_bob = zethUtils.get_private_key_from_bytes(keypair_bob_bytes[1])

  # Subtest 1: Alice to Alice
  ciphertext_alice_alice = zethUtils.encrypt(message, pk_alice, sk_alice)
  plaintext_alice_alice = zethUtils.decrypt(ciphertext_alice_alice, pk_alice, sk_alice)
  assert plaintext_alice_alice == message, "Error in Alice to Alice test"

  # Subest 2: Bob to Alice
  ciphertext_bob_alice = zethUtils.encrypt(message, pk_alice, sk_bob)
  plaintext_bob_alice = zethUtils.decrypt(ciphertext_bob_alice, pk_alice, sk_bob)
  assert plaintext_bob_alice == message, "Error in Bob to Alice test: pk_alice, sk_bob"
  plaintext_bob_alice = zethUtils.decrypt(ciphertext_bob_alice, pk_bob, sk_alice)
  assert plaintext_bob_alice == message, "Error in Bob to Alice test: pk_bob, sk_alice"

  print("Tests encrypt_decrypt passed")

if __name__ == "__main__":
  test_encrypt_decrypt()
