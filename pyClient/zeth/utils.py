# Parse the arguments given to the script

from . import constants
from . import errors

import argparse
import sys
import os
import time
from os.path import join, dirname, normpath
# Import Pynacl required modules
from eth_abi import encode_single
import nacl.utils  # type: ignore
from nacl.public import PrivateKey, PublicKey, Box  # type: ignore
from web3 import Web3, HTTPProvider  # type: ignore

w3 = Web3(HTTPProvider(constants.WEB3_HTTP_PROVIDER))

# Value of a single unit (in Wei) of vpub_in and vpub_out.  Use Szabos (10^12
# Wei).
ZETH_PUBLIC_UNIT_VALUE = 1000000000000


def int64_to_hex(number):
    return '{:016x}'.format(number)


def hex_digest_to_binary_string(digest):
    def binary(x):
        zipped = zip(
            *[["{0:04b}".format(int(c, 16)) for c in reversed("0"+x)][n::2]
              for n in [1, 0]])
        return "".join(reversed(
            [i+j for i, j in zipped]))
    return binary(digest)


def hex2int(elements):
    """
    Given an error of hex strings, return an array of int values
    """
    ints = []
    for el in elements:
        ints.append(int(el, 16))
    return(ints)


def hex_extend_32bytes(element):
    """
    Extend a hex string to represent 32 bytes
    """
    res = str(element)
    if len(res) % 2 != 0:
        res = "0" + res
    res = "00"*int((64-len(res))/2) + res
    return res


def hex_digest_to_bits(digest):
    padded = "0" + digest
    digest_bits = ["{0:04b}".format(int(c, 16)) for c in reversed(padded)]
    zipped = zip(*[digest_bits[n::2] for n in [1, 0]])
    return "".join(reversed([i+j for i, j in zipped]))


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
    Decrypts a string message by using valid ec25519 public key and private key
    objects.  See: https://pynacl.readthedocs.io/en/stable/public/
    """

    # Init encryption box instance
    decryption_box = Box(sk_receiver, pk_sender)

    # Check integrity of the ciphertext and decrypt it
    message = decryption_box.decrypt(encrypted_message)
    return str(message, encoding='utf-8')


def convert_leaf_address_to_node_address(address_leaf, tree_depth):
    """
    Converts the relative address of a leaf to an absolute address in the tree
    Important note: The merkle root index is 0 (not 1!)
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
        coin_filename = \
            "{}_{}.json".format(username, int(round(time.time() * 1000)))
        path_to_coin = os.path.join(coinstore_dir, coin_filename)
        file = open(path_to_coin, "w")
        file.write(recovered_plaintext)
        file.close()
    except Exception as e:
        print(f"[ERROR] in receive. Might not be the recipient! (msg: {e})")
    return recovered_plaintext


def parse_zksnark_arg():
    """
    Parse the zksnark argument and return its value
    """
    parser = argparse.ArgumentParser(
        description="Testing Zeth transactions using the specified zkSNARK " +
        "('GROTH16' or 'PGHR13').\nNote that the zkSNARK must match the one " +
        "used on the prover server.")
    parser.add_argument("zksnark", help="Set the zkSNARK to use")
    args = parser.parse_args()
    if args.zksnark not in constants.VALID_ZKSNARKS:
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


def to_zeth_units(value, unit):
    return int(Web3.toWei(value, unit) / ZETH_PUBLIC_UNIT_VALUE)


def get_zeth_dir():
    return os.environ.get(
        'ZETH',
        normpath(join(dirname(__file__), "..", "..")))


def get_trusted_setup_dir():
    return os.environ.get(
        'ZETH_TRUSTED_SETUP_DIR',
        join(get_zeth_dir(), "trusted_setup"))


def get_contracts_dir():
    return os.environ.get(
        'ZETH_CONTRACTS_DIR',
        join(get_zeth_dir(), "zeth-contracts", "contracts"))


def encode_to_hash(messages):
    """
    Encode a list of variables, or list of lists of variables into a byte
    vector
    """
    input_sha = bytearray()

    # Flatten messages
    if any(isinstance(el, list) for el in messages):
        new_list = []
        for el in messages:
            if type(el) == list:
                new_list.extend(el)
            else:
                new_list.append(el)
        messages = new_list

    for m in messages:
        # For each element
        m_hex = m

        # Convert it into a hex
        if type(m) == int:
            m_hex = "{0:0>4X}".format(m)
        elif (type(m) == str) and (m[1] == "x"):
            m_hex = m[2:]

        # [SANITY CHECK] Make sure the hex is 32 byte long
        m_hex = hex_extend_32bytes(m_hex)

        # Encode the hex into a byte array and append it to result
        input_sha += encode_single("bytes32", bytes.fromhex(m_hex))

    return input_sha
