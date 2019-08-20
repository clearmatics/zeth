# Parse the arguments given to the script
import argparse
import sys

import os
import time

# Import Pynacl required modules
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

import zethGRPC

# Import the constants and standard errors defined for zeth
import zethConstants as constants
import zethErrors as errors

from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
w3 = Web3(HTTPProvider(constants.WEB3_HTTP_PROVIDER))

# Gets PrivateKey object from hexadecimal representation (see: https://pynacl.readthedocs.io/en/stable/public/#nacl.public.PrivateKey)
def get_private_key_from_hex(private_key_hex):
  return PrivateKey(private_key_hex, encoder=nacl.encoding.HexEncoder)

# Gets PublicKey object from hexadecimal representation (see: https://pynacl.readthedocs.io/en/stable/public/#nacl.public.PublicKey)
def get_public_key_from_hex(public_key_hex):
  return PublicKey(public_key_hex, encoder=nacl.encoding.HexEncoder)

# Encrypts a string message by using valid hexadecimal ec25519 public and private keys. See: https://pynacl.readthedocs.io/en/stable/public/
def encrypt(message, public_key_hex, private_key_hex):
  # Decodes hex representation to keys objects
  private_key = get_private_key_from_hex(private_key_hex)
  public_key = get_public_key_from_hex(public_key_hex)

  # Inits encryption box instance
  encryption_box = Box(private_key, public_key)

  # Encods str message to bytes
  message_bytes = message.encode('utf-8')

  # Encrypts the message. The nonce is chosen randomly.
  encrypted = encryption_box.encrypt(message_bytes, encoder=nacl.encoding.HexEncoder)

  return str(encrypted, encoding = 'utf-8')

# Decrypts a string ciphertext by using valid hexadecimal ec25519 public and private keys. See: https://pynacl.readthedocs.io/en/stable/public/
def decrypt(encrypted_message, public_key_hex, private_key_hex):
  # Decode hex to keys objects
  private_key = get_private_key_from_hex(private_key_hex)
  public_key = get_public_key_from_hex(public_key_hex)

  # Inits encryption box instance
  decryption_box = Box(private_key, public_key)

  # Checks integrity of the ciphertext and decrypts it
  message = decryption_box.decrypt(bytes(encrypted_message, encoding ='utf-8'), encoder=nacl.encoding.HexEncoder)

  return str(message, encoding = 'utf-8')

# Converts the realtive address of a leaf to an absolute address in the tree
# Important note: The merkle root index 0 (not 1!)
def convert_leaf_address_to_node_address(address_leaf, tree_depth):
    address = address_leaf + (2 ** tree_depth - 1)
    if(address > 2 ** (tree_depth + 1) - 1):
        return -1
    return address

def compute_merkle_path(address_commitment, tree_depth, byte_tree):
    merkle_path = []
    address_bits = []
    address = convert_leaf_address_to_node_address(address_commitment, tree_depth)
    if(address == -1):
        return merkle_path # return empty merkle_path
    for i in range (0 , tree_depth):
        address_bits.append(address % 2)
        if (address % 2 == 0):
            print("append note at address: " + str(address - 1))
            merkle_path.append(w3.toHex(byte_tree[address - 1])[2:]) # [2:] to strip the 0x prefix
            address = int(address/2) - 1 # - 1 because we decided to start counting from 0 (which is the index of the root node)
        else:
            print("append note at address: " + str(address + 1))
            merkle_path.append(w3.toHex(byte_tree[address + 1])[2:])
            address = int(address/2)
    return merkle_path

def receive(ciphertext, public_key_hex, private_key_hex, username):
    recovered_plaintext = ""
    try:
        recovered_plaintext = decrypt(ciphertext, public_key_hex, private_key_hex)
        print("[INFO] {} recovered one plaintext".format(username.capitalize()))
        print("[INFO] {} received a payment!".format(username.capitalize()))
        # Just as an example we write the received coin in the coinstore
        print("[INFO] Writing the received note in the coinstore")
        coinstore_dir = os.environ['ZETH_COINSTORE']
        coin_filename = "{}_{}.json".format(username, int(round(time.time() * 1000)))
        path_to_coin = os.path.join(coinstore_dir, coin_filename)
        file = open(path_to_coin, "w")
        file.write(recovered_plaintext)
        file.close()
    except Exception as e:
        print("[ERROR] in receive. Might not be the recipient! (msg: {})".format(e))
    return recovered_plaintext

# Parse the zksnark argument and return its value
def parse_zksnark_arg():
    parser = argparse.ArgumentParser(description="Testing Zeth transactions using the specified zkSNARK ('GROTH16' or 'PGHR13'). Note that the zkSNARK must match the one used on the prover server.")
    parser.add_argument("zksnark", help="Set the zkSNARK to use")
    args = parser.parse_args()
    if (args.zksnark not in [constants.PGHR13_ZKSNARK, constants.GROTH16_ZKSNARK]):
        return sys.exit(errors.SNARK_NOT_SUPPORTED)
    return args.zksnark

# Generates private/public keys (kP, k) over Curve25519 for Alice, Bob and Charlie
def gen_keys_utility(to_print=False):
  # Alice
  skalice = PrivateKey.generate()
  skalice_hex = skalice.encode(encoder=nacl.encoding.HexEncoder)
  pkalice_hex = skalice.public_key.encode(encoder=nacl.encoding.HexEncoder)

  alice_keys_hex = [pkalice_hex, skalice_hex]

  # Bob
  skbob = PrivateKey.generate()
  skbob_hex = skbob.encode(encoder=nacl.encoding.HexEncoder)
  pkbob_hex = skbob.public_key.encode(encoder=nacl.encoding.HexEncoder)

  bob_keys_hex = [pkbob_hex, skbob_hex]

  # Charlie
  skcharlie = PrivateKey.generate()
  skcharlie_hex = skcharlie.encode(encoder=nacl.encoding.HexEncoder)
  pkcharlie_hex = skcharlie.public_key.encode(encoder=nacl.encoding.HexEncoder)

  charlie_keys_hex = [pkcharlie_hex, skcharlie_hex]

  if to_print:
    print("Alice")
    print(pkalice_hex)
    print(skalice_hex)

    print("Bob")
    print(pkbob_hex)
    print(skbob_hex)

    print("Charlie")
    print(pkcharlie_hex)
    print(skcharlie_hex)

  return alice_keys_hex, bob_keys_hex, charlie_keys_hex
