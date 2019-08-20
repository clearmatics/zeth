# Set of tests for zethUtils.py

import zethMock
import zethUtils

from nacl.public import PrivateKey, PublicKey
from nacl.encoding import HexEncoder

def test_get_private_key_from_hex():
  private_key_obj = zethUtils.get_private_key_from_hex(keystore["Alice"]["AddrSk"]["privkey"])

  private_key = PrivateKey(keystore["Alice"]["AddrSk"]["privkey"], encoder=HexEncoder)

  assert private_key_obj == private_key, "private key not correct"
  print("Test get_private_key_from_hex passed")

def test_get_public_key_from_hex():
  public_key_obj = zethUtils.get_public_key_from_hex(keystore["Alice"]["AddrPk"]["pubkey"])

  public_key = PublicKey(keystore["Alice"]["AddrPk"]["pubkey"], encoder=HexEncoder)

  assert public_key_obj == public_key, "public key not correct"
  print("Test get_public_key_from_hex passed")

def test_encrypt_decrypt():

  message = b"Kill all humans"

  alice_keys_hex, bob_keys_hex, _ = zethUtils.gen_keys_utility()

  pkalice_hex = alice_keys_hex[0]
  skalice_hex = alice_keys_hex[1]

  pkbob_hex = bob_keys_hex[0]
  skbob_hex = bob_keys_hex[1]

  # Subtest 1: Alice to Alice
  ciphertext_alice_alice = zethUtils.encrypt(message, pkalice_hex, skalice_hex)
  plaintext = zethUtils.decrypt(ciphertext_alice_alice, pkalice_hex, skalice_hex)

  assert plaintext == str(message, encoding='utf-8'), "error in Alice to Alice test"

  # Subest 2: Alice to Bob
  ciphertext_alice_bob = zethUtils.encrypt(message, pkalice_hex, skbob_hex)
  plaintext2 = zethUtils.decrypt(ciphertext_alice_bob, pkalice_hex, skbob_hex)
  assert plaintext == str(message, encoding='utf-8'), "error in Bob to Alice test"

  plaintext2 = zethUtils.decrypt(ciphertext_alice_bob, pkbob_hex, skalice_hex)
  assert plaintext == str(message, encoding='utf-8'), "error in Bob to Alice test"

  print("Tests encrypt_decrypt passed")

if __name__ == "__main__":

  keystore = zethMock.initTestKeystore()

  test_get_private_key_from_hex()
  test_get_public_key_from_hex()
  test_encrypt_decrypt()
