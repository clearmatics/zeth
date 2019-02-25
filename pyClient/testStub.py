import random
import logging
import json
import os
import time

from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider

# Do RPC calls
import grpc

# Get the utils to deploy and call the contracts
import zethContracts
# Get the utils written to interact with the prover
import zethGRPC
# Get the mock data for the test
import zethMock

w3 = Web3(HTTPProvider("http://localhost:8545"));
test_grpc_endpoint = 'localhost:50051'

def get_proof_bob_deposit(keystore, mk_root):
    print("Bob deposits 4 ETH for himself and splits them into note1: 2ETH, note2: 2ETH")
    zero_wei_hex = "0000000000000000"

    # Here Bob is the recipient of the newly generated notes
    bob_apk = keystore["Bob"]["AddrPk"]["aPK"]
    bob_ask = keystore["Bob"]["AddrSk"]["aSK"]

    # Create the JoinSplit inputs
    #
    # Dummy note 1
    input_note1 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), bob_apk, zero_wei_hex)
    input_nullifier1 = zethGRPC.computeNullifier(input_note1, bob_ask)
    address_note1 = 7
    # Dummy note 2
    input_note2 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), bob_apk, zero_wei_hex)
    input_nullifier2 = zethGRPC.computeNullifier(input_note2, bob_ask)
    address_note2 = 8

    dummy_mk_path = [
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    ]
    js_inputs = [
        zethGRPC.createJSInput(dummy_mk_path, address_note1, input_note1, bob_ask, input_nullifier1),
        zethGRPC.createJSInput(dummy_mk_path, address_note2, input_note2, bob_ask, input_nullifier2)
    ]

    # Create the JoinSplit outputs
    #
    # Note 1: value 2ETH
    value_output_note1 = zethGRPC.int64ToHexadecimal(Web3.toWei('2', 'ether'))
    output_note1 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), bob_apk, value_output_note1)
    # Note 2: value 2ETH
    value_output_note2 = zethGRPC.int64ToHexadecimal(Web3.toWei('2', 'ether'))
    output_note2 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), bob_apk, value_output_note2)
    js_outputs = [
        output_note1,
        output_note2
    ]

    input_pub_val = zethGRPC.int64ToHexadecimal(Web3.toWei('4', 'ether'))
    output_pub_val = zero_wei_hex

    proof_input = zethGRPC.makeProofInputs(mk_root, js_inputs, js_outputs, input_pub_val, output_pub_val)
    proof_obj = zethGRPC.getProof(test_grpc_endpoint, proof_input)
    proof_json = zethGRPC.parseProof(proof_obj)

    # We return the zeth notes to be able to spend them later
    # and the proof used to create them
    return (output_note1, output_note2, proof_json)

def bob_deposit(mixer_instance, mk_root, bob_eth_address):
    print(" === Bob deposits 4ETH for him ===")
    (output_note1, output_note2, proof_json) = get_proof_bob_deposit(keystore, mk_root)
    output_note1_str = json.dumps(zethGRPC.parseZethNote(output_note1))
    output_note2_str = json.dumps(zethGRPC.parseZethNote(output_note2))
    return zethContracts.mix(
        mixer_instance,
        output_note1_str,
        output_note2_str,
        proof_json,
        bob_eth_address,
        w3.toWei(4, 'ether'),
        4000000
    )

def getProofForAliceDeposit():
    print("Alice deposits 1 ETH for Charlie and 1 ETH for her")
    keystore = zethMock.initTestKeystore()
    zeroWeiHex = "0000000000000000"

    charlieAPK = keystore["Charlie"]["AddrPk"]["aPK"] # we generate a coin for Charlie (recipient1)
    charlieASK = keystore["Charlie"]["AddrSk"]["aSK"]
    aliceAPK = keystore["Alice"]["AddrPk"]["aPK"] # we generate a coin for Alice (recipient2)
    aliceASK = keystore["Alice"]["AddrSk"]["aSK"]

    # Dummy note 1
    noteAliceIn1 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), aliceAPK, zeroWeiHex)
    nullifierIn1 = zethGRPC.computeNullifier(noteAliceIn1, aliceASK)
    addressNote1 = 7
    # Dummy note 2
    noteAliceIn2 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), aliceAPK, zeroWeiHex)
    nullifierIn2 = zethGRPC.computeNullifier(noteAliceIn2, aliceASK)
    addressNote2 = 8

    dummyRoot = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    dummyMerklePath = [
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    ]
    jsInputs = [
        zethGRPC.createJSInput(dummyMerklePath, addressNote1, noteAliceIn1, aliceASK, nullifierIn1),
        zethGRPC.createJSInput(dummyMerklePath, addressNote2, noteAliceIn2, aliceASK, nullifierIn2)
    ]

    # Note 1
    noteValueOut1 = zethGRPC.int64ToHexadecimal(Web3.toWei('1', 'ether')) # Note of value 1 as output of the JS
    noteCharlieOut1 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), charlieAPK, noteValueOut1)
    # Note 2
    noteValueOut2 = zethGRPC.int64ToHexadecimal(Web3.toWei('1', 'ether')) # Note of value 1 as output of the JS
    noteAliceOut2 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), aliceAPK, noteValueOut2)
    jsOutputs = [
        noteCharlieOut1,
        noteAliceOut2
    ]

    inPubValue = zethGRPC.int64ToHexadecimal(Web3.toWei('2', 'ether'))
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
    deployer_eth_address = w3.eth.accounts[0]
    bob_eth_address = w3.eth.accounts[1]
    alice_eth_address = w3.eth.accounts[2]
    charlie_eth_address = w3.eth.accounts[3]

    # Zeth addresses
    keystore = zethMock.initTestKeystore()

    # Depth of the merkle tree (need to match the one used in the cpp prover)
    mk_tree_depth = 4

    print("[TEST DEBUG] 1. Fetching the verification key from the proving server")
    vk = zethGRPC.getVerificationKey(test_grpc_endpoint)
    print("[TEST DEBUG] 2. Received VK, writing the key...")
    zethGRPC.writeVerificationKey(vk)
    print("[TEST DEBUG] 3. VK written, deploying the smart contracts...")
    (mixer_instance, initial_root) = zethContracts.deploy(mk_tree_depth, deployer_eth_address, 4000000)
    print("[TEST DEBUG] 4. Running tests...")
    (cm_address1, cm_address2, new_mk_root, ciphertext1, ciphertext2) = bob_deposit(mixer_instance, initial_root, bob_eth_address)
    print("cm_address1: ")
    print(cm_address1)
    print("cm_address2: ")
    print(cm_address2)
    print("new_mk_root: ")
    print(new_mk_root)
    print("ciphertext1: ")
    print(ciphertext1)
    print("ciphertext2: ")
    print(ciphertext2)
