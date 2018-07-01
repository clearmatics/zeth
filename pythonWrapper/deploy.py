import json
import web3
import hashlib
import subprocess
import shlex
import logging

from web3 import Web3, HTTPProvider, TestRPCProvider
from solc import compile_source, compile_standard
from web3.contract import ConciseContract

import pdb
from solc import compile_source, compile_files, link_code
from bitstring import BitArray
import random 

from ctypes import cdll
import ctypes as c

w3 = Web3(HTTPProvider("http://localhost:8545"));

def hex2int(elements):
    ints = []
    for el in elements:
        ints.append(int(el, 16))
    return(ints)

def compile():
    Miximus = "../contracts/Miximus.sol"
    MerkleTree = "../contracts/MerkleTree.sol"  
    Pairing =  "../contracts/Pairing.sol"
    Verifier = "../contracts/Verifier.sol"

    compiled_sol =  compile_files([Pairing, MerkleTree, Pairing, Verifier, Miximus], allow_paths="./contracts")
    miximus_interface = compiled_sol[Miximus + ':Miximus']
    verifier_interface = compiled_sol[Verifier + ':Verifier']
    return(miximus_interface, verifier_interface)
   
def deploy(path_to_vk):
    miximus_interface , verifier_interface  = compile()
    with open(path_to_vk) as json_data:
        vk = json.load(json_data)
    vk  = [
        hex2int(vk["a"][0]),
        hex2int(vk["a"][1]),
        hex2int(vk["b"]),
        hex2int(vk["c"][0]),
        hex2int(vk["c"][1]),
        hex2int(vk["g"][0]),
        hex2int(vk["g"][1]),
        hex2int(vk["gb1"]),
        hex2int(vk["gb2"][0]),
        hex2int(vk["gb2"][1]),
        hex2int(vk["z"][0]),
        hex2int(vk["z"][1]),
        hex2int(sum(vk["IC"], []))
    ]

    # Instantiate and deploy contract
    miximus = w3.eth.contract(abi=miximus_interface['abi'], bytecode=miximus_interface['bin'])
    verifier = w3.eth.contract(abi=verifier_interface['abi'], bytecode=verifier_interface['bin'])

    # Get transaction hash from deployed Verifier contract
    tx_hash = verifier.deploy(transaction={'from': w3.eth.accounts[0], 'gas': 4000000}, args=vk)

    # Get tx receipt to get Verifier contract address
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    verifier_address = tx_receipt['contractAddress']
    print("[INFO] Verifier address: ", verifier_address)

    # Deploy the Miximus contract once the Verifier is successfully deployed
    tx_hash = miximus.deploy(transaction={'from': w3.eth.accounts[0], 'gas': 4000000}, args=[verifier_address])

    # Get tx receipt to get Miximus contract address
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    miximus_address = tx_receipt['contractAddress']
    print("[INFO] Miximus address: ", miximus_address)

    # Contract instance in concise mode
    abi = miximus_interface['abi']
    miximus = w3.eth.contract(address=miximus_address, abi=abi, ContractFactoryClass=ConciseContract)

    return(miximus)

def deposit_call(miximus, nullifier, sk, depositAddress):
    # leaf = miximus.getSha256(nullifier, sk) # TODO: implement my sha256 hash function to avoid leaking the secret
    commitment = '0x' + computeCommitment(nullifier, sk)
    print("[DEBUG] leaf/commitment from Python code: ", commitment)
    #print("[DEBUG] leaf/commitment from Solidity code: ", w3.toHex(leaf))
    print("[DEBUG] nullifier: ", nullifier)
    print("[DEBUG] sk: ", sk)

    tx_hash = miximus.deposit(commitment, transact={'from': depositAddress, 'gas': 4000000, "value": w3.toWei(1, "ether")})
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    return tx_receipt

def deposit(miximus, senderAddress, recipientAddress):
    nullifier = generateNullifier(recipientAddress)
    secret = generateSecret()
    resDeposit = deposit_call(miximus, nullifier, secret, senderAddress)
    return(resDeposit, nullifier, secret)

def withdraw(miximus, path_to_proof, withdrawAddress):
    with open(path_to_proof) as json_data:
        proof = json.load(json_data)

    tx_hash = miximus.withdraw(
        hex2int(proof["a"]),
        hex2int(proof["a_p"]), 
        [hex2int(proof["b"][0]), hex2int(proof["b"][1])],
        hex2int(proof["b_p"]),
        hex2int(proof["c"]),
        hex2int(proof["c_p"]),
        hex2int(proof["h"]),
        hex2int(proof["k"]),
        hex2int(proof["input"]),
        transact={'from': withdrawAddress, 'gas': 4000000}
    )
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    print(w3.eth.getBalance(miximus.address))

# TODO: Wrapper around withdraw function
def redeemPrivatePayment(miximus, withdrawAddress, unspentCommitment, position):
    tree = miximus.getTree()
    generateProof(tree, 4, 16, secret, nullifier, unspentCommitment) # Call the C++ cli prove command
    withdraw(miximus, "../zksnark_element/proof.json", withdrawAddress)

# Generates the proof needed to spend the given commitment
def generateProof(tree, tree_depth, addressLeaf, sk, nullifier, commitment):
    merkle_path = computeMerklePath(addressLeaf, tree_depth, tree)
    root = tree[1]
    proveCmdArgs = [
        '../build/src/main',
        'prove', 
        str(tree_depth),
        str(addressLeaf),
        sk,
        nullifier[2:],
        commitment[2:],
        root.hex()
    ]
    for node in merkle_path:
        proveCmdArgs.append(node.hex())
    proveCmd = " ".join(map(str, proveCmdArgs))
    print("Running command:", proveCmd)
    # We run the C++ CLI command prove to generate the proof
    run_command(proveCmd)

# Taken from: https://www.endpoint.com/blog/2015/01/28/getting-realtime-output-using-python
def run_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell = True, encoding='utf8')
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            print(output.strip())
    rc = process.poll()
    return rc

# TODO: Implement the foward function
#def forward(miximus, path_to_proof, commitment, withdrawAddress):
#    with open(path_to_proof) as json_data:
#        pk = json.load(json_data)
#    print(w3.eth.getBalance(miximus.address))
#    tx_hash = miximus.withdraw(pk["a"] , pk["a_p"], pk["b"], pk["b_p"] , pk["c"], pk["c_p"] , pk["h"] , pk["k"], pk["input"] , transact={'from': withdrawAddress, 'gas': 4000000})
#    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
#    print(w3.eth.getBalance(miximus.address))
#
#def forwardPrivatePayment(miximus, senderAddress, recipientAddress):
#    generateProof()
#    nullifier = generateNullifier(recipientAddress)
#    secret = generateSecret()
#    forward(miximus, nullifier, secret, senderAddress)

def bytesToBinary(hexString):
    out = "" 
    for i, byte in enumerate(hexString):
        out += bin(byte)[2:].rjust(8,"0")
    out = [int(x) for x in out] 
    return((c.c_bool*256)(*out))
    pk = "asdf"

def generateSalt(i):
    salt = [random.choice("123456789abcdef") for x in range(0,i)]
    out = "".join(salt)
    return(out)

def generateNullifier(recvAddress):
    salt = generateSalt(24)
    return(recvAddress + salt)

def generateSecret():
    secret = generateSalt(64)
    return secret

# ------------------------------------------- #

def computeCommitment(nullifier, secret):
    m = hashlib.sha256()
    m.update(bytearray.fromhex(nullifier[2:]))
    m.update(bytearray.fromhex(secret))
    return m.hexdigest()

# We differentiate between leaf address (which is the position of a leaf in the leaf array)
# And the address of a node which is the address of a node in the tree
# For example, in a tree of depth 4, there are 2^4 leaves, and there are 2^5 - 1 nodes
# Thus the leafAddress of the first leaf is: 0 (first element of the leaf array)
# and its nodeAddress is 16 (because the same leaf appears in the 16th position in the array of nodes of the tree)
def convertLeafAddressToNodeAddress(addressLeaf, tree_depth):
    address = addressLeaf + 2 ** tree_depth
    if(address > 2 ** (tree_depth+1) - 1): # Total number of nodes in the tree, so if address > to this, the address given is invalid
        return -1 # return empty merkle_path
    return address


def computeMerklePath(addressCommitment, tree_depth, tree):
    merkle_path = []
    address_bits = []
    address = convertLeafAddressToNodeAddress(addressCommitment, tree_depth)
    if(address == -1):
        return merkle_path # return empty merkle_path
    for i in range (0 , tree_depth):
        address_bits.append(address % 2)
        if (address %2 == 0) :
            merkle_path.append(tree[address + 1])
        else:
            merkle_path.append(tree[address - 1])
        address = int(address/2) 
    return merkle_path[::-1]


## MAIN
def main():
    senderAddress = w3.eth.accounts[0]
    recipientAddress = w3.eth.accounts[3]

    print("Start contracts deployment")
    path_to_vk = "../zksnark_element/vk.json"
    miximus_instance = deploy(path_to_vk)

    print("Miximus balance before deposit --> ", w3.eth.getBalance(miximus_instance.address))
    print("Call deposit")
    resDeposit, nullifier, secret = deposit(miximus_instance, senderAddress, recipientAddress)
    print("Miximus balance after deposit --> ", w3.eth.getBalance(miximus_instance.address))

    tree = miximus_instance.getTree()
    #print("TREE")
    #for node in tree:
    #    print("NODE: ", node.hex())
    #    print("\n")
    unspentCommitment = '0x' + computeCommitment(nullifier, secret)
    generateProof(tree, 4, 0, secret, nullifier, unspentCommitment) # Call the C++ cli prove command

    print("Miximus balance before withdraw --> ", w3.eth.getBalance(miximus_instance.address))
    print("Recipient balance before withdraw --> ", w3.eth.getBalance(recipientAddress))
    withdraw(miximus_instance, "./proof.json", recipientAddress)
    print("Recipient balance after withdraw --> ", w3.eth.getBalance(recipientAddress))
    print("Miximus balance after withdraw --> ", w3.eth.getBalance(miximus_instance.address))

if __name__== "__main__":
     main()
