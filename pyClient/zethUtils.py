from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import zlib
import base64

# Parse the arguments given to the script
import argparse
import sys

import zethGRPC

# Import the constants and standard errors defined for zeth
import zethConstants as constants
import zethErrors as errors

from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
w3 = Web3(HTTPProvider("http://localhost:8545"))

"""
Note: In this proof of concept we encrypt the notes' data with RSA-OAEP.
This scheme is known not to be IK-CCA. As a consequence, it is fundamental
to switch to an encryption scheme that is IK-CCA to fully meet the privacy
promises of ZETH.

Reference:
 - [BBDP01]:
   "Key-Privacy in Public-Key Encryption",
   M. Bellare, A. Boldyreva, A. Desai, and D. Pointcheval,
   Asiacrypt 2001,
   <https://iacr.org/archive/asiacrypt2001/22480568.pdf>
"""
def encrypt(message, public_key):
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    blob = zlib.compress(message.encode())

    # Refer to: https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html#Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher.encrypt
    # to define the chunk size
    chunk_size = 62 # (128 - 2 - 2*32) since we use RSA modulus of 1024 bits (128 bytes) in the keystore
    offset = 0
    end_loop = False
    encrypted =  "".encode()

    while not end_loop:
        chunk = blob[offset:offset + chunk_size]

        # Padding
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += " ".encode() * (chunk_size - len(chunk))

        encrypted += rsa_key.encrypt(chunk)
        offset += chunk_size

    return base64.b64encode(encrypted)

def decrypt(encrypted_blob, private_key):
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    encrypted_blob = base64.b64decode(encrypted_blob)

    chunk_size = 128 # Size of the modulus we use here
    offset = 0
    decrypted = "".encode()

    # Loop over our chunks
    while offset < len(encrypted_blob):
        chunk = encrypted_blob[offset: offset + chunk_size]
        decrypted += rsakey.decrypt(chunk)
        offset += chunk_size
    return str(zlib.decompress(decrypted), 'utf-8')

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
    return merkle_path[::-1] # Return the merkle tree in reverse order

def receive(ciphertext, decryption_key, username):
    recovered_plaintext = ""
    try:
        recovered_plaintext = decrypt(ciphertext, decryption_key)
        print("[INFO] {} recovered one plaintext".format(username))
        print("[INFO] {} received a payment!".format(username))
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
    parser = argparse.ArgumentParser(description="Testing Zeth transactions using an ERC token using the specified zkSNARK ('GROTH16' or 'PGHR13'). Note that the zkSNARK must match the one used on the prover server.")
    parser.add_argument("zksnark", help="Set the zkSNARK to use")
    args = parser.parse_args()
    if (args.zksnark not in [constants.PGHR13_ZKSNARK, constants.GROTH16_ZKSNARK]):
        return sys.exit(errors.SNARK_NOT_SUPPORTED)
    return args.zksnark
