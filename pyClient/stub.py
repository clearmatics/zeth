import random
import logging
import json
import os
import time

from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
from web3.contract import ConciseContract
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
    path_to_bytes = os.path.join(contractsDir, "Bytes.sol")
    path_to_verifier = os.path.join(contractsDir, "Verifier.sol")
    path_to_wrapperVerifier = os.path.join(contractsDir, "WrapperVerifier.sol")
    path_to_mixer = os.path.join(contractsDir, "Mixer.sol")
    compiled_sol = compile_files([path_to_pairing, path_to_bytes, path_to_verifier, path_to_wrapperVerifier, path_to_mixer])
    verifier_interface = compiled_sol[path_to_verifier + ':Verifier']
    wrapper_verifier_interface = compiled_sol[path_to_wrapperVerifier + ':WrapperVerifier']
    mixer_interface = compiled_sol[path_to_mixer + ':Mixer']
    return(wrapper_verifier_interface, verifier_interface, mixer_interface)

def hex2int(elements):
    ints = []
    for el in elements:
        ints.append(int(el, 16))
    return(ints)

def deploy():
    wrapper_verifier_interface, verifier_interface, mixer_interface = compileContracts()
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

    # Deploy the Mixer contract once the Verifier is successfully deployed
    mixer = w3.eth.contract(abi=mixer_interface['abi'], bytecode=mixer_interface['bin'])
    tx_hash = mixer.constructor(
        _zksnark_verify=verifier_address,
        depth=4
    ).transact({'from': w3.eth.accounts[0], 'gas': 4000000})
    # Get tx receipt to get Mixer contract address
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    mixer_address = tx_receipt['contractAddress']
    print("[INFO] Mixer address: ", mixer_address)

    # Get contract instances
    wrapper_verifier = w3.eth.contract(
        address=wrapper_verifier_address,
        abi=wrapper_verifier_interface['abi']
    )
    mixer = w3.eth.contract(
        address=mixer_address,
        abi=mixer_interface['abi']
    )

    # Get the initial merkle root to proceed to the first payments
    event_filter_logMerkleRoot = mixer.eventFilter("LogMerkleRoot", {'fromBlock': 0, 'toBlock': 'latest'})
    event_logs_logMerkleRoot = event_filter_logMerkleRoot.get_all_entries()
    initialRoot = w3.toHex(event_logs_logMerkleRoot[0].args.root)
    print("Initial root hex: " +  initialRoot)
    return(wrapper_verifier, mixer, initialRoot[2:])

def mix(mixer, parsedProof, senderAddress, weiPubValue):
    tx_hash = mixer.functions.mix(
        "should be ciphertext1",
        "should be ciphertext 2",
        hex2int(parsedProof["a"]),
        hex2int(parsedProof["a_p"]),
        [hex2int(parsedProof["b"][0]), hex2int(parsedProof["b"][1])],
        hex2int(parsedProof["b_p"]),
        hex2int(parsedProof["c"]),
        hex2int(parsedProof["c_p"]),
        hex2int(parsedProof["h"]),
        hex2int(parsedProof["k"]),
        hex2int(parsedProof["inputs"])
    ).transact({'from': senderAddress, 'value': weiPubValue, 'gas': 4000000})
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    # Gather the addresses of the appended commitments
    event_filter_logAddress = mixer.eventFilter("LogAddress", {'fromBlock': 'latest', 'toBlock': 'latest'})
    event_logs_logAddress = event_filter_logAddress.get_all_entries()
    # Get the new merkle root
    event_filter_logMerkleRoot = mixer.eventFilter("LogMerkleRoot", {'fromBlock': 'latest', 'toBlock': 'latest'})
    event_logs_logMerkleRoot = event_filter_logMerkleRoot.get_all_entries()
    # Get the ciphertexts
    event_filter_logSecretCiphers = mixer.eventFilter("LogSecretCiphers", {'fromBlock': 'latest', 'toBlock': 'latest'})
    event_logs_logSecretCiphers = event_filter_logSecretCiphers.get_all_entries()

    print("event_logs_logAddress: ")
    print(event_logs_logAddress)
    print("event_logs_logMerkleRoot: ")
    print(event_logs_logMerkleRoot)
    print("event_logs_logSecretCiphers: ")
    print(event_logs_logSecretCiphers)

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

def getRoot(mixer_instance):
    tx_hash = mixer_instance.functions.getRoot().transact({'from': w3.eth.accounts[0], 'gas': 4000000})
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    event_filter = wrapper_verifier.eventFilter("LogDebug", {'fromBlock': 0, 'toBlock': 'latest'})
    event_logs = event_filter.get_all_entries()
    root = event_logs[0].args.text
    print("Event text: " + event_logs[0].args.text)
    print("Event name: " + event_logs[0].event)

def getProofForBobDeposit(root):
    print("Bob deposits 4 ETH for himself and splits them into note1: 2ETH, note2: 2ETH")
    keystore = zeth.initTestKeystore()
    zeroWeiHex = "0000000000000000"

    bobAPK = keystore["Bob"]["AddrPk"]["aPK"] # we generate a coin for Bob (recipient)
    bobASK = keystore["Bob"]["AddrSk"]["aSK"]

    # Dummy note 1
    noteBobIn1 = zeth.createZethNote(zeth.noteRandomness(), bobAPK, zeroWeiHex)
    nullifierIn1 = zeth.computeNullifier(noteBobIn1, bobASK)
    addressNote1 = 7
    # Dummy note 2
    noteBobIn2 = zeth.createZethNote(zeth.noteRandomness(), bobAPK, zeroWeiHex)
    nullifierIn2 = zeth.computeNullifier(noteBobIn2, bobASK)
    addressNote2 = 8

    #dummyRoot = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    dummyRoot = root
    dummyMerklePath = [
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    ]
    jsInputs = [
        zeth.createJSInput(dummyMerklePath, addressNote1, noteBobIn1, bobASK, nullifierIn1),
        zeth.createJSInput(dummyMerklePath, addressNote2, noteBobIn2, bobASK, nullifierIn2)
    ]

    # Note 1
    noteValueOut1 = zeth.int64ToHexadecimal(Web3.toWei('2', 'ether')) # Note of value 2 as output of the JS
    noteBobOut1 = zeth.createZethNote(zeth.noteRandomness(), bobAPK, noteValueOut1)
    # Note 2
    noteValueOut2 = zeth.int64ToHexadecimal(Web3.toWei('2', 'ether')) # Note of value 2 as output of the JS
    noteBobOut2 = zeth.createZethNote(zeth.noteRandomness(), bobAPK, noteValueOut2)
    jsOutputs = [
        noteBobOut1,
        noteBobOut2
    ]

    inPubValue = zeth.int64ToHexadecimal(Web3.toWei('4', 'ether'))
    outPubValue = zeroWeiHex

    proofInput = makeProofInputs(dummyRoot, jsInputs, jsOutputs, inPubValue, outPubValue)
    proofObj = getProof(proofInput)
    proofJSON = parseProof(proofObj)

    # We return the zeth notes to be able to spend them later
    # and the proof used to create them
    return (noteBobOut1, noteBobOut2, proofJSON)

def bobDeposit(mixer_instance, root, bobEthAddress):
    print(" === Bob deposits 4ETH for him ===")
    (noteBobOut1, noteBobOut2, proof) = getProofForBobDeposit(root)
    mix(mixer_instance, proof, bobEthAddress, w3.toWei(4, 'ether'))

def getProofForAliceDeposit():
    print("Alice deposits 1 ETH for Charlie and 1 ETH for her")
    keystore = zeth.initTestKeystore()
    zeroWeiHex = "0000000000000000"

    charlieAPK = keystore["Charlie"]["AddrPk"]["aPK"] # we generate a coin for Charlie (recipient1)
    charlieASK = keystore["Charlie"]["AddrSk"]["aSK"]
    aliceAPK = keystore["Alice"]["AddrPk"]["aPK"] # we generate a coin for Alice (recipient2)
    aliceASK = keystore["Alice"]["AddrSk"]["aSK"]

    # Dummy note 1
    noteAliceIn1 = zeth.createZethNote(zeth.noteRandomness(), aliceAPK, zeroWeiHex)
    nullifierIn1 = zeth.computeNullifier(noteAliceIn1, aliceASK)
    addressNote1 = 7
    # Dummy note 2
    noteAliceIn2 = zeth.createZethNote(zeth.noteRandomness(), aliceAPK, zeroWeiHex)
    nullifierIn2 = zeth.computeNullifier(noteAliceIn2, aliceASK)
    addressNote2 = 8

    dummyRoot = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    dummyMerklePath = [
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    ]
    jsInputs = [
        zeth.createJSInput(dummyMerklePath, addressNote1, noteAliceIn1, aliceASK, nullifierIn1),
        zeth.createJSInput(dummyMerklePath, addressNote2, noteAliceIn2, aliceASK, nullifierIn2)
    ]

    # Note 1
    noteValueOut1 = zeth.int64ToHexadecimal(Web3.toWei('1', 'ether')) # Note of value 1 as output of the JS
    noteCharlieOut1 = zeth.createZethNote(zeth.noteRandomness(), charlieAPK, noteValueOut1)
    # Note 2
    noteValueOut2 = zeth.int64ToHexadecimal(Web3.toWei('1', 'ether')) # Note of value 1 as output of the JS
    noteAliceOut2 = zeth.createZethNote(zeth.noteRandomness(), aliceAPK, noteValueOut2)
    jsOutputs = [
        noteCharlieOut1,
        noteAliceOut2
    ]

    inPubValue = zeth.int64ToHexadecimal(Web3.toWei('2', 'ether'))
    outPubValue = zeroWeiHex

    proofInput = makeProofInputs(dummyRoot, jsInputs, jsOutputs, inPubValue, outPubValue)
    proofObj = getProof(proofInput)
    proofJSON = parseProof(proofObj)

    # We return the zeth notes to be able to spend them later
    # and the proof used to create them
    return (noteCharlieOut1, noteAliceOut2, proofJSON)

def aliceDeposit(wrapper_verifier_instance):
    print(" === Alice deposits 2ETH: 1ETH for Charlie, and 1ETH for her ===")
    (noteCharlieOut1, noteAliceOut2, proof) = getProofForAliceDeposit()
    verify(wrapper_verifier_instance, proof)

if __name__ == '__main__':
    # Ethereum addresses
    bobEthAddress = w3.eth.accounts[1]
    aliceEthAddress = w3.eth.accounts[2]
    charlieEthAddress = w3.eth.accounts[3]

    # Zeth addresses
    zethKeystore = zeth.initTestKeystore()

    print("[DEBUG] 1. Fetching the verification key from the proving server")
    vk = getVerificationKey()
    print("[DEBUG] 2. Received VK, writing the key...")
    writeVerificationKey(vk)
    print("[DEBUG] 3. VK written, deploying the smart contracts...")
    (wrapper_verifier_instance, mixer_instance, initialRoot) = deploy()
    print("[DEBUG] Running tests...")
    bobDeposit(mixer_instance, initialRoot, bobEthAddress)
    #aliceDeposit(wrapper_verifier_instance)
