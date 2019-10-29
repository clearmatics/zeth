# Parse the arguments given to the script

import zeth.constants as constants
import zeth.errors as errors

import argparse
import sys
import os
import time
from os.path import join, dirname
# Import Pynacl required modules
import nacl.utils  # type: ignore
from nacl.public import PrivateKey, PublicKey, Box  # type: ignore
from web3 import Web3, HTTPProvider  # type: ignore

w3 = Web3(HTTPProvider(constants.WEB3_HTTP_PROVIDER))

# Value of a single unit (in Wei) of vpub_in and vpub_out.  Use Szabos (10^12
# Wei).
ZETH_PUBLIC_UNIT_VALUE = 1000000000000


def get_private_key_from_bytes(sk_bytes):
    """
    Gets PrivateKey object from hexadecimal representation
    (see: https://pynacl.readthedocs.io/en/stable/public/#nacl.public.PrivateKey)
    """
    return PrivateKey(sk_bytes, encoder=nacl.encoding.RawEncoder)


def get_public_key_from_bytes(pk_bytes):
    """
    Gets PublicKey object from hexadecimal representation
    (see: https://pynacl.readthedocs.io/en/stable/public/#nacl.public.PublicKey)
    """
    return PublicKey(pk_bytes, encoder=nacl.encoding.RawEncoder)


def encrypt(message, pk_receiver, sk_sender):
    """
    Encrypts a string message by using valid ec25519 public key and
    private key objects. See: https://pynacl.readthedocs.io/en/stable/public/
    """
    # Init encryption box instance
    encryption_box = Box(sk_sender, pk_receiver)

    # Encode str message to bytes
    message_bytes = message.encode('utf-8')

    # Encrypt the message. The nonce is chosen randomly.
    encrypted = encryption_box.encrypt(message_bytes, encoder=nacl.encoding.RawEncoder)

    # Need to cast to the parent class Bytes of nacl.utils.EncryptedMessage
    # to make it accepted from `Mix` Solidity function
    return bytes(encrypted)


def decrypt(encrypted_message, pk_sender, sk_receiver):
    """
    Decrypts a string message by using valid ec25519 public key and private key objects.
    See: https://pynacl.readthedocs.io/en/stable/public/
    """

    # Init encryption box instance
    decryption_box = Box(sk_receiver, pk_sender)

    # Check integrity of the ciphertext and decrypt it
    message = decryption_box.decrypt(encrypted_message)
    return str(message, encoding='utf-8')


def convert_leaf_address_to_node_address(address_leaf, tree_depth):
    """
# Converts the realtive address of a leaf to an absolute address in the tree
# Important note: The merkle root index 0 (not 1!)
    """
    address = address_leaf + (2 ** tree_depth - 1)
    if(address > 2 ** (tree_depth + 1) - 1):
        return -1
    return address


def compute_merkle_path(address_commitment, tree_depth, byte_tree):
    merkle_path = []
    address_bits = []
    address = convert_leaf_address_to_node_address(address_commitment, tree_depth)
    if(address == -1):
        return merkle_path  # return empty merkle_path
    for i in range(0, tree_depth):
        address_bits.append(address % 2)
        if (address % 2 == 0):
            print("append note at address: " + str(address - 1))
            # [2:] to strip the 0x prefix
            merkle_path.append(w3.toHex(byte_tree[address - 1])[2:])
            # -1 because we decided to start counting from 0 (which is the
            # index of the root node)
            address = int(address/2) - 1
        else:
            print("append note at address: " + str(address + 1))
            merkle_path.append(w3.toHex(byte_tree[address + 1])[2:])
            address = int(address/2)
    return merkle_path


def receive(ciphertext, pk_sender, sk_receiver, username):
    recovered_plaintext = ""
    try:
        recovered_plaintext = decrypt(ciphertext, pk_sender, sk_receiver)
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


def parse_zksnark_arg():
    """
    Parse the zksnark argument and return its value
    """
    parser = argparse.ArgumentParser(
        description="Testing Zeth transactions using the specified zkSNARK " +
        "('GROTH16' or 'PGHR13'). Note that the zkSNARK must match the one " +
        "used on the prover server.")
    parser.add_argument("zksnark", help="Set the zkSNARK to use")
    args = parser.parse_args()
    if (args.zksnark not in [constants.PGHR13_ZKSNARK, constants.GROTH16_ZKSNARK]):
        return sys.exit(errors.SNARK_NOT_SUPPORTED)
    return args.zksnark


def gen_keys_utility(to_print=False):
    """
    Generates private/public keys (kP, k) over Curve25519 for Alice, Bob and
    Charlie
    """
    # Encoder
    encoder = nacl.encoding.RawEncoder

    # Alice
    sk_alice = PrivateKey.generate()
    sk_alice_bytes = sk_alice.encode(encoder)
    pk_alice_bytes = sk_alice.public_key.encode(encoder)

    alice_keys_bytes = [pk_alice_bytes, sk_alice_bytes]

    # Bob
    sk_bob = PrivateKey.generate()
    sk_bob_bytes = sk_bob.encode(encoder)
    pk_bob_bytes = sk_bob.public_key.encode(encoder)

    bob_keys_bytes = [pk_bob_bytes, sk_bob_bytes]

    # Charlie
    sk_charlie = PrivateKey.generate()
    sk_charlie_bytes = sk_charlie.encode(encoder)
    pk_charlie_bytes = sk_charlie.public_key.encode(encoder)

    charlie_keys_bytes = [pk_charlie_bytes, sk_charlie_bytes]

    if to_print:
        print("Alice")
        print(pk_alice_bytes)
        print(sk_alice_bytes)

        print("Bob")
        print(pk_bob_bytes)
        print(sk_bob_bytes)

        print("Charlie")
        print(pk_charlie_bytes)
        print(sk_charlie_bytes)

    return alice_keys_bytes, bob_keys_bytes, charlie_keys_bytes


def toZethUnits(value, unit):
    return int(Web3.toWei(value, unit) / ZETH_PUBLIC_UNIT_VALUE)


def get_zeth_dir():
    return os.environ.get(
        'ZETH_TRUSTED_SETUP_DIR',
        join(dirname(__file__), "..", ".."))


def get_trusted_setup_dir():
    return os.environ.get(
        'ZETH_TRUSTED_SETUP_DIR',
        join(dirname(__file__), "..", "..", "trusted_setup"))


def get_contracts_dir():
    return os.environ.get(
        'ZETH_CONTRACTS_DIR',
        join(dirname(__file__), "..", "..", "zeth-contracts", "contracts"))
