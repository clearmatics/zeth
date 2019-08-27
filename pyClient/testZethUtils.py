import zethUtils

from nacl.public import PrivateKey, PublicKey

# Tests the correct encrypt-decrypt flow: decrypt(encrypt(m)) == m
def test_encrypt_decrypt():

  message = "Kill all humans"

  alice_keys_bytes, bob_keys_bytes, _ = zethUtils.gen_keys_utility()

  pkalice_bytes = alice_keys_bytes[0]
  skalice = zethUtils.get_private_key_from_bytes(alice_keys_bytes[1])

  pkbob_bytes = bob_keys_bytes[0]
  skbob = zethUtils.get_private_key_from_bytes(bob_keys_bytes[1])

  # Subtest 1: Alice to Alice
  ciphertext_alice_alice = zethUtils.encrypt(message, pkalice_bytes, skalice)

  plaintext_alice_alice = zethUtils.decrypt(ciphertext_alice_alice, pkalice_bytes, skalice)
  assert plaintext_alice_alice == message, "error in Alice to Alice test"

  # Subest 2: Bob to Alice
  ciphertext_bob_alice = zethUtils.encrypt(message, pkalice_bytes, skbob)

  plaintext_bob_alice = zethUtils.decrypt(ciphertext_bob_alice, pkalice_bytes, skbob)
  assert plaintext_bob_alice == message, "error in Bob to Alice test: pkalice,skbob"

  plaintext_bob_alice = zethUtils.decrypt(ciphertext_bob_alice, pkbob_bytes, skalice)
  assert plaintext_bob_alice == message, "error in Bob to Alice test: pkbob,skalice"

  print("Tests encrypt_decrypt passed")

if __name__ == "__main__":

  test_encrypt_decrypt()
