import json
import web3
import subprocess

from web3 import Web3, HTTPProvider
from utils import hex2int, generateNullifier, generateSecret, computeCommitment, computeMerklePath

w3 = Web3(HTTPProvider("http://localhost:8545"));

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

# TODO: Fix bad proof when we call the forward function
def forward(miximus, path_to_proof, withdrawAddress, recipientAddress):
    # Generate new commitment for the recipient
    newNullifier = generateNullifier(recipientAddress)
    newSecret = generateSecret()
    newCommitment = '0x' + computeCommitment(newNullifier, newSecret)

    # Proof that we can spend this "unspent" commitment
    with open(path_to_proof) as json_data:
        proof = json.load(json_data)
    tx_hash = miximus.forward(
        newCommitment,
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
    return(tx_receipt, newNullifier, newSecret)
