import zethMock
import zethUtils

from nacl.public import PrivateKey, PublicKey
from nacl.encoding import HexEncoder

# Test we get the correct PrivateKey object from the hexadecimal encoding
def test_get_private_key_from_hex():
  private_key_obj = zethUtils.get_private_key_from_hex(keystore["Alice"]["AddrSk"]["privkey"])

  private_key = PrivateKey(keystore["Alice"]["AddrSk"]["privkey"], encoder=HexEncoder)

  assert private_key_obj == private_key, "private key not correct"
  print("Test get_private_key_from_hex passed")

# Test we get the correct PublicKey object from the hexadecimal encoding
def test_get_public_key_from_hex():
  public_key_obj = zethUtils.get_public_key_from_hex(keystore["Alice"]["AddrPk"]["pubkey"])

  public_key = PublicKey(keystore["Alice"]["AddrPk"]["pubkey"], encoder=HexEncoder)

  assert public_key_obj == public_key, "public key not correct"
  print("Test get_public_key_from_hex passed")

# Test correct encrypt-decrypt flow: decrypt(encrypt(m)) == m
def test_encrypt_decrypt():

  message = "Kill all humans"

  alice_keys_hex, bob_keys_hex, _ = zethUtils.gen_keys_utility()

  pkalice_hex = alice_keys_hex[0]
  skalice_hex = alice_keys_hex[1]

  pkbob_hex = bob_keys_hex[0]
  skbob_hex = bob_keys_hex[1]

  # Subtest 1: Alice to Alice
  ciphertext_alice_alice = zethUtils.encrypt(message, pkalice_hex, skalice_hex)

  plaintext_alice_alice = zethUtils.decrypt(ciphertext_alice_alice, pkalice_hex, skalice_hex)
  assert plaintext_alice_alice == message, "error in Alice to Alice test"

  # Subest 2: Bob to Alice
  ciphertext_bob_alice = zethUtils.encrypt(message, pkalice_hex, skbob_hex)

  plaintext_bob_alice = zethUtils.decrypt(ciphertext_bob_alice, pkalice_hex, skbob_hex)
  assert plaintext_bob_alice == message, "error in Bob to Alice test: pkalice,skbob"

  plaintext_bob_alice = zethUtils.decrypt(ciphertext_bob_alice, pkbob_hex, skalice_hex)
  assert plaintext_bob_alice == message, "error in Bob to Alice test: pkbob,skalice"

  print("Tests encrypt_decrypt passed")

if __name__ == "__main__":

  keystore = zethMock.initTestKeystore()

  test_get_private_key_from_hex()
  test_get_public_key_from_hex()
  test_encrypt_decrypt()
