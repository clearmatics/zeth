import random
import logging
import json
import os
import time

from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
from web3.contract import ConciseContract
#from solc import compile_source, compile_standard
#from solc import compile_source, compile_files, link_code
from solcx import compile_standard, compile_files

# Get the utils written to interact with the prover
import zethUtils as zeth

# grpc modules
import grpc
import prover_pb2
import prover_pb2_grpc

w3 = Web3(HTTPProvider("http://localhost:8545"));

def make_empty_message():
    return prover_pb2.EmptyMessage()

# Fetch the verification kwy from the proving service
def getVerificationKey():
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = prover_pb2_grpc.ProverStub(channel)
        print("-------------- GetVerificationKey --------------")
        verificationkey = stub.GetVerificationKey(make_empty_message());
        return verificationkey # verificationKey is an object here

def parseVerificationKey(vkObj):
    vkJSON = {}
    vkJSON["a"] = zeth.parseHexadecimalPointBaseGroup2Affine(vkObj.a)
    vkJSON["b"] = zeth.parseHexadecimalPointBaseGroup1Affine(vkObj.b)
    vkJSON["c"] = zeth.parseHexadecimalPointBaseGroup2Affine(vkObj.c)
    vkJSON["g"] = zeth.parseHexadecimalPointBaseGroup2Affine(vkObj.g)
    vkJSON["gb1"] = zeth.parseHexadecimalPointBaseGroup1Affine(vkObj.gb1)
    vkJSON["gb2"] = zeth.parseHexadecimalPointBaseGroup2Affine(vkObj.gb2)
    vkJSON["z"] = zeth.parseHexadecimalPointBaseGroup2Affine(vkObj.z)
    vkJSON["IC"] = json.loads(vkObj.IC)
    return vkJSON

# Writes the verification key (object) in a json file
def writeVerificationKey(vkObj):
    vkJSON = parseVerificationKey(vkObj)
    setupDir = os.environ['ZETH_TRUSTED_SETUP_DIR']
    filename = os.path.join(setupDir, "vk.json")
    with open(filename, 'w') as outfile:
        json.dump(vkJSON, outfile)

def makeProofInputs(root, jsInputs, jsOutputs, inPubValue, outPubValue):
    return prover_pb2.ProofInputs(
        root=root,
        jsInputs=jsInputs,
        jsOutputs=jsOutputs,
        inPubValue=inPubValue,
        outPubValue=outPubValue
    )

def getProof(proofInputs):
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = prover_pb2_grpc.ProverStub(channel)
        print("-------------- GetProof --------------")
        proof = stub.Prove(proofInputs)
        return proof # proof is an object here

def parseProof(proofObj):
    proofJSON = {}
    proofJSON["a"] = zeth.parseHexadecimalPointBaseGroup1Affine(proofObj.a)
    proofJSON["a_p"] = zeth.parseHexadecimalPointBaseGroup1Affine(proofObj.aP)
    proofJSON["b"] = zeth.parseHexadecimalPointBaseGroup2Affine(proofObj.b)
    proofJSON["b_p"] = zeth.parseHexadecimalPointBaseGroup1Affine(proofObj.bP)
    proofJSON["c"] = zeth.parseHexadecimalPointBaseGroup1Affine(proofObj.c)
    proofJSON["c_p"] = zeth.parseHexadecimalPointBaseGroup1Affine(proofObj.cP)
    proofJSON["h"] = zeth.parseHexadecimalPointBaseGroup1Affine(proofObj.h)
    proofJSON["k"] = zeth.parseHexadecimalPointBaseGroup1Affine(proofObj.k)
    proofJSON["inputs"] = json.loads(proofObj.inputs)
    return proofJSON

def compileContracts():
    contractsDir = os.environ['ZETH_CONTRACTS_DIR']
    path_to_pairing = os.path.join(contractsDir, "Pairing.sol")
    path_to_verifier = os.path.join(contractsDir, "Verifier.sol")
    path_to_wrapperVerifier = os.path.join(contractsDir, "WrapperVerifier.sol")
    compiled_sol = compile_files([path_to_pairing, path_to_verifier, path_to_wrapperVerifier])
    verifier_interface = compiled_sol[path_to_verifier + ':Verifier']
    wrapper_verifier_interface = compiled_sol[path_to_wrapperVerifier + ':WrapperVerifier']
    return(wrapper_verifier_interface, verifier_interface)

def hex2int(elements):
    ints = []
    for el in elements:
        ints.append(int(el, 16))
    return(ints)

def deploy():
    wrapper_verifier_interface, verifier_interface = compileContracts()
    setupDir = os.environ['ZETH_TRUSTED_SETUP_DIR']
    vk_json = os.path.join(setupDir, "vk.json")
    with open(vk_json) as json_data:
        vk = json.load(json_data)

    # Instantiate and deploy the verifier contract
    verifier = w3.eth.contract(abi=verifier_interface['abi'], bytecode=verifier_interface['bin'])
    tx_hash = verifier.constructor(
        A1=hex2int(vk["a"][0]),
        A2=hex2int(vk["a"][1]),
        B=hex2int(vk["b"]),
        C1=hex2int(vk["c"][0]),
        C2=hex2int(vk["c"][1]),
        gamma1=hex2int(vk["g"][0]),
        gamma2=hex2int(vk["g"][1]),
        gammaBeta1=hex2int(vk["gb1"]),
        gammaBeta2_1=hex2int(vk["gb2"][0]),
        gammaBeta2_2=hex2int(vk["gb2"][1]),
        Z1=hex2int(vk["z"][0]),
        Z2=hex2int(vk["z"][1]),
        input=hex2int(sum(vk["IC"], []))
    ).transact({'from': w3.eth.accounts[0], 'gas': 4000000})
    # Get tx receipt to get Verifier contract address
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    verifier_address = tx_receipt['contractAddress']
    print("[INFO] Verifier address: ", verifier_address)

    # Deploy the wrapperVerifier contract once the Verifier is successfully deployed
    wrapper_verifier = w3.eth.contract(abi=wrapper_verifier_interface['abi'], bytecode=wrapper_verifier_interface['bin'])
    tx_hash = wrapper_verifier.constructor(
        _zksnark_verify=verifier_address
    ).transact({'from': w3.eth.accounts[0], 'gas': 4000000})
    # Get tx receipt to get WrapperVerifier contract address
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    wrapper_verifier_address = tx_receipt['contractAddress']
    print("[INFO] WrapperVerifier address: ", wrapper_verifier_address)
    # Contract instance in concise mode
    wrapper_verifier = w3.eth.contract(
        address=wrapper_verifier_address,
        abi=wrapper_verifier_interface['abi']
    )
    return(wrapper_verifier)

def verify(wrapper_verifier, parsedProof):
    tx_hash = wrapper_verifier.functions.verify(
        hex2int(parsedProof["a"]),
        hex2int(parsedProof["a_p"]),
        [hex2int(parsedProof["b"][0]), hex2int(parsedProof["b"][1])],
        hex2int(parsedProof["b_p"]),
        hex2int(parsedProof["c"]),
        hex2int(parsedProof["c_p"]),
        hex2int(parsedProof["h"]),
        hex2int(parsedProof["k"]),
        hex2int(parsedProof["inputs"])
    ).transact({'from': w3.eth.accounts[0], 'gas': 4000000})
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    event_filter = wrapper_verifier.eventFilter("LogDebug", {'fromBlock': 0, 'toBlock': 'latest'})
    event_logs = event_filter.get_all_entries()
    print("Event text: " + event_logs[0].args.text)
    print("Event name: " + event_logs[0].event)

def getProofTestCase1():
    print("Test case 1: Bob deposits 4 ETH for himself")
    keystore = zeth.initTestKeystore()
    zeroWei = "0000000000000000000"
    zeroWeiHex = "0000000000000000"

    bobAPK = keystore["Bob"]["AddrPk"]["aPK"] # we generate a coin for Bob (recipient)
    bobASK = keystore["Bob"]["AddrSk"]["aSK"]
    print("Bob keys")
    print(bobAPK)
    print(bobASK)

    noteBobIn = zeth.createZethNote(zeth.noteRandomness(), bobAPK, zeroWeiHex)
    nullifierIn = zeth.computeNullifier(noteBobIn, bobASK)

    root = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    merklePath = [
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    ]
    jsInputs = [
        zeth.createJSInput(merklePath, 7, noteBobIn, bobASK, nullifierIn)
    ]

    valueOut = zeth.int64ToHexadecimal(Web3.toWei('4', 'ether')) # Note of value 4 as output of the JS
    noteBobOut = zeth.createZethNote(zeth.noteRandomness(), bobAPK, valueOut)
    nullifierOut = zeth.computeNullifier(noteBobOut, bobASK)
    jsOutputs = [
        noteBobOut
    ]

    inPubValue = zeth.int64ToHexadecimal(Web3.toWei('4', 'ether'))
    outPubValue = zeroWeiHex # No pub output

    proofInput = makeProofInputs(root, jsInputs, jsOutputs, inPubValue, outPubValue)
    proofObj = getProof(proofInput)
    proofJSON = parseProof(proofObj)
    return proofJSON

def testCase1(wrapper_verifier_instance):
    print(" === TestCase 1 ===")
    print("[TestCase1] Get proof from server")
    parsedProof = getProofTestCase1()
    print("[TestCase1] Verifying proof")
    verify(wrapper_verifier_instance, parsedProof)

if __name__ == '__main__':
    print("[DEBUG] Fetching the verification key from the proving server")
    vk = getVerificationKey()
    print("[DEBUG] Received VK, writing the key...")
    writeVerificationKey(vk)
    print("[DEBUG] VK written, deploying the smart contracts...")
    wrapper_verifier_instance = deploy()
    testCase1(wrapper_verifier_instance)
