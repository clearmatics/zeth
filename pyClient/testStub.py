import json
import os

from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider

# Get the utils to deploy and call the contracts
import zethContracts
# Get the utils written to interact with the prover
import zethGRPC
# Get the mock data for the test
import zethMock
# Get the utils to encrypt/decrypt
import zethUtils

w3 = Web3(HTTPProvider("http://localhost:8545"))
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

def bob_deposit(mixer_instance, mk_root, bob_eth_address, keystore):
    print(" === Bob deposits 4ETH for him ===")
    (output_note1, output_note2, proof_json) = get_proof_bob_deposit(keystore, mk_root)
    output_note1_str = json.dumps(zethGRPC.parseZethNote(output_note1))
    output_note2_str = json.dumps(zethGRPC.parseZethNote(output_note2))
    ciphertext1 = zethUtils.encrypt(output_note1_str, keystore["Bob"]["AddrPk"]["ek"])
    ciphertext2 = zethUtils.encrypt(output_note2_str, keystore["Bob"]["AddrPk"]["ek"])
    return zethContracts.mix(
        mixer_instance,
        ciphertext1,
        ciphertext2,
        proof_json,
        bob_eth_address,
        w3.toWei(4, 'ether'),
        4000000
    )

def get_proof_bob_transfer_to_charlie(keystore, mk_root, mk_path, input_note1, address_note1):
    print("Bob transfers 1 ETH to Charlie from his funds on the mixer")
    zero_wei_hex = "0000000000000000"

    charlie_apk = keystore["Charlie"]["AddrPk"]["aPK"] # We generate a coin for Charlie (recipient1)
    bob_apk = keystore["Bob"]["AddrPk"]["aPK"] # We generate a coin for Bob: the change (recipient2)
    bob_ask = keystore["Bob"]["AddrSk"]["aSK"] # Bob is the sender

    # Note 1: The note Bob spends for his transfer
    input_nullifier1 = zethGRPC.computeNullifier(input_note1, bob_ask)

    # Note 2: This note is a dummy note
    input_note2 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), bob_apk, zero_wei_hex)
    input_nullifier2 = zethGRPC.computeNullifier(input_note2, bob_ask)
    address_note2 = 8

    js_inputs = [
        zethGRPC.createJSInput(mk_path, address_note1, input_note1, bob_ask, input_nullifier1),
        zethGRPC.createJSInput(mk_path, address_note2, input_note2, bob_ask, input_nullifier2)
    ]

    # Create the JoinSplit outputs
    #
    # Note 1: value 2ETH
    value_output_note1 = zethGRPC.int64ToHexadecimal(Web3.toWei('1', 'ether'))
    output_note1 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), bob_apk, value_output_note1)
    # Note 2: value 2ETH
    value_output_note2 = zethGRPC.int64ToHexadecimal(Web3.toWei('1', 'ether'))
    output_note2 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), charlie_apk, value_output_note2)
    js_outputs = [
        output_note1,
        output_note2
    ]

    input_pub_val = zero_wei_hex
    output_pub_val = zero_wei_hex

    proof_input = zethGRPC.makeProofInputs(mk_root, js_inputs, js_outputs, input_pub_val, output_pub_val)
    proof_obj = zethGRPC.getProof(test_grpc_endpoint, proof_input)
    proof_json = zethGRPC.parseProof(proof_obj)

    # We return the zeth notes to be able to spend them later
    # and the proof used to create them
    return (output_note1, output_note2, proof_json)

def bob_to_charlie(mixer_instance, mk_root, mk_path, input_note1, address_note1, bob_eth_address, keystore):
    print(" === Bob transfers 1ETH to Charlie ===")
    (output_note1, output_note2, proof_json) = get_proof_bob_transfer_to_charlie(
        keystore,
        mk_root,
        mk_path,
        input_note1,
        address_note1
    )
    output_note1_str = json.dumps(zethGRPC.parseZethNote(output_note1))
    output_note2_str = json.dumps(zethGRPC.parseZethNote(output_note2))
    ciphertext1 = zethUtils.encrypt(output_note1_str, keystore["Bob"]["AddrPk"]["ek"]) # Bob is the recipient
    ciphertext2 = zethUtils.encrypt(output_note2_str, keystore["Charlie"]["AddrPk"]["ek"]) # Charlie is the recipient
    return zethContracts.mix(
        mixer_instance,
        ciphertext1,
        ciphertext2,
        proof_json,
        bob_eth_address,
        w3.toWei(1, 'wei'), # Pay an arbitrary amount (1 wei here) that will be refunded since the `mix` function is payable
        4000000
    )

def get_proof_charlie_withdraw(keystore, mk_root, mk_path, input_note1, address_note1):
    print("Charlie withdraws 0.9ETH from his funds on the mixer")
    zero_wei_hex = "0000000000000000"

    charlie_apk = keystore["Charlie"]["AddrPk"]["aPK"] # We generate a coin of value 0.1ETH for Charlie (recipient)
    charlie_ask = keystore["Charlie"]["AddrSk"]["aSK"] # Charlie is the sender

    # Note 1: The note Charlie splits and spends for his withdrawal
    input_nullifier1 = zethGRPC.computeNullifier(input_note1, charlie_ask)

    # Note 2: This note is a dummy note
    input_note2 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), charlie_apk, zero_wei_hex)
    input_nullifier2 = zethGRPC.computeNullifier(input_note2, charlie_ask)
    address_note2 = 8

    js_inputs = [
        zethGRPC.createJSInput(mk_path, address_note1, input_note1, charlie_ask, input_nullifier1),
        zethGRPC.createJSInput(mk_path, address_note2, input_note2, charlie_ask, input_nullifier2)
    ]

    # Create the JoinSplit outputs
    #
    # Note 1: value 0.1ETH
    value_output_note1 = zethGRPC.int64ToHexadecimal(Web3.toWei('0.1', 'ether'))
    output_note1 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), charlie_apk, value_output_note1)
    # Note 2: value 0ETH
    value_output_note2 = zero_wei_hex
    output_note2 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), charlie_apk, value_output_note2)
    js_outputs = [
        output_note1,
        output_note2
    ]

    input_pub_val = zero_wei_hex
    output_pub_val = zethGRPC.int64ToHexadecimal(Web3.toWei('0.9', 'ether'))

    proof_input = zethGRPC.makeProofInputs(mk_root, js_inputs, js_outputs, input_pub_val, output_pub_val)
    proof_obj = zethGRPC.getProof(test_grpc_endpoint, proof_input)
    proof_json = zethGRPC.parseProof(proof_obj)

    # We return the zeth notes to be able to spend them later
    # and the proof used to create them
    return (output_note1, output_note2, proof_json)

def charlie_withdraw(mixer_instance, mk_root, mk_path, input_note1, address_note1, charlie_eth_address, keystore):
    print(" === Charlie withdraws 0.9 ===")
    (output_note1, output_note2, proof_json) = get_proof_charlie_withdraw(
        keystore,
        mk_root,
        mk_path,
        input_note1,
        address_note1
    )
    output_note1_str = json.dumps(zethGRPC.parseZethNote(output_note1))
    output_note2_str = json.dumps(zethGRPC.parseZethNote(output_note2))
    ciphertext1 = zethUtils.encrypt(output_note1_str, keystore["Charlie"]["AddrPk"]["ek"]) # Charlie is the recipient
    ciphertext2 = zethUtils.encrypt(output_note2_str, keystore["Charlie"]["AddrPk"]["ek"]) # Charlie is the recipient
    return zethContracts.mix(
        mixer_instance,
        ciphertext1,
        ciphertext2,
        proof_json,
        charlie_eth_address,
        w3.toWei(1, 'wei'), # Pay an arbitrary amount (1 wei here) that will be refunded since the `mix` function is payable
        4000000
    )

def print_balances(bob, alice, charlie, mixer):
    print("Bob's ETH balance: ", w3.eth.getBalance(bob))
    print("Alice's ETH balance: ", w3.eth.getBalance(alice))
    print("Charlie's ETH balance: ", w3.eth.getBalance(charlie))
    print("Mixer's ETH balance: ", w3.eth.getBalance(mixer))

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

    print("[INFO] 1. Fetching the verification key from the proving server")
    vk = zethGRPC.getVerificationKey(test_grpc_endpoint)

    print("[INFO] 2. Received VK, writing the key...")
    zethGRPC.writeVerificationKey(vk)

    print("[INFO] 3. VK written, deploying the smart contracts...")
    (mixer_instance, initial_root) = zethContracts.deploy(mk_tree_depth, deployer_eth_address, 4000000)

    print("[INFO] 4. Running tests...")
    print("Initial balances: ")
    print_balances(bob_eth_address, alice_eth_address, charlie_eth_address, mixer_instance.address)

    # Bob deposits 4ETH split in 2 notes of denominations of 2ETh and 2ETH on the mixer
    (cm_address1BtB, cm_address2BtB, new_mk_rootBtB, ciphertext1BtB, ciphertext2BtB) = bob_deposit(mixer_instance, initial_root, bob_eth_address, keystore)

    print("Balances after Bob's deposit: ")
    print_balances(bob_eth_address, alice_eth_address, charlie_eth_address, mixer_instance.address)

    # Alice sees a deposit and tries to decrypt the ciphertexts to see if she was the recipient
    # But she wasn't the recipient (Bob was), so she fails to decrypt
    try:
        bob_recovered_plaintext1 = zethUtils.decrypt(ciphertext1BtB, keystore["Alice"]["AddrSk"]["dk"])
        bob_recovered_plaintext2 = zethUtils.decrypt(ciphertext2BtB, keystore["Alice"]["AddrSk"]["dk"])
        print("/!\ Alice recovered the 2 plaintext encrypted by Bob for Bob!!!")
        print("Recovered plaintext1: " + bob_recovered_plaintext1 + " plaintext2: " + bob_recovered_plaintext2)
    except:
        print("Alice tried to decrypt ciphertexts that were not dedicated to her, and failed!")

    # Bob does a transfer of 1ETH to Charlie on the mixer
    # Bob looks in the merkle tree and gets the merkle path to the commitment he wants to spend
    mk_byte_tree = mixer_instance.functions.getTree().call()
    print("[DEBUG] Displaying the merkle tree maintained by the mixer contract: ")
    for node in mk_byte_tree:
        print("Node: " + w3.toHex(node)[2:])

    # Get the merkle path for the commitment to spend
    mk_path = zethUtils.compute_merkle_path(cm_address1BtB, mk_tree_depth, mk_byte_tree)

    # Bob decrypts one of the note he previously received (useless here but useful if the payment came from someone else)
    input_note_json = json.loads(zethUtils.decrypt(ciphertext1BtB, keystore["Bob"]["AddrSk"]["dk"]))
    input_noteBtC = zethGRPC.zethNoteObjFromParsed(input_note_json)

    # TODO: Recompute the commitment from the coin's data (to check the validity of the payment)
    # TODO: Make sure this recomputed commitment is equal to the commitment at address cm_address1BtB
    (cm_address1_bob_transfer, cm_address2_bob_transfer, new_mk_root_bob_transfer, ciphertext1_bob_transfer, ciphertext2_bob_transfer) = bob_to_charlie(mixer_instance, new_mk_rootBtB, mk_path, input_noteBtC, cm_address1BtB, bob_eth_address, keystore)

    # Bob tries to do a double spent (spending the zeth note `input_noteBtC,` twice)
    try:
        (cm_address1_bob_transfer_ds, cm_address2_bob_transfer_ds, new_mk_root_bob_transfer_ds, ciphertext1_bob_transfer_ds, ciphertext2_bob_transfer_ds) = bob_to_charlie(mixer_instance, new_mk_rootBtB, mk_path, input_noteBtC, cm_address1BtB, bob_eth_address, keystore)
        print("/!\ Double spent successful for Bob!")
    except:
        print("Bob tried to use the same commitment twice (double spent) as input of the joinsplit, and failed!")

    print("Balances after Bob's transfer to Charlie: ")
    print_balances(bob_eth_address, alice_eth_address, charlie_eth_address, mixer_instance.address)

    # TODO: Charlie withdraws 0.9 ETH and keeps 0.1ETH in the mixer
    # Charlie tries to decrypt the ciphertexts from Bob's previous transaction
    recovered_plaintext1 = ""
    try:
        recovered_plaintext1 = decrypt(ciphertext1_bob_transfer, keystore["Charlie"]["AddrSk"]["dk"])
        print("[INFO] Charlie recovered one of the plaintext encrypted by Bob!")
        print("[INFO] Charlie now knows he received a payment from Bob.")
    except:
        print("[ERROR] Charlie failed to decrypt a ciphertext emitted by Bob's transaction: Was not the recipient!")
    recovered_plaintext2 = ""
    try:
        recovered_plaintext2 = zethUtils.decrypt(ciphertext2_bob_transfer, keystore["Charlie"]["AddrSk"]["dk"])
        print("[INFO] Charlie recovered one of the plaintext encrypted by Bob!")
        print("[INFO] Charlie now knows he received a payment from Bob.")
        # Just as an example we write the received coin in the coinstore
        print("[INFO] Writing the received note in the coinstore")
        coinstore_dir = os.environ['ZETH_COINSTORE']
        path_to_coin = os.path.join(coinstore_dir, "note_from_bob_test.json")
        file = open(path_to_coin, "w")
        file.write(recovered_plaintext2)
        file.close()
    except:
        print("[ERROR] Charlie failed to decrypt a ciphertext emitted by Bob's transaction: Was not the recipient!")

    # Here `recovered_plaintext1` should contain a valid note in json str format and `recovered_plaintext2` should be the empty string
    assert (recovered_plaintext1 == ""),"`recovered_plaintext1` Should be the empty string since the 1st note of Bob's transfer was his change"
    assert (recovered_plaintext2 != ""),"`recovered_plaintext2` Should contain a valid note in json str format"


    # Charlie now gets the merkle path for the commitment he wants to spend
    mk_byte_tree = mixer_instance.functions.getTree().call()
    print("[DEBUG] Displaying the merkle tree maintained by the mixer contract: ")
    for node in mk_byte_tree:
        print("Node: " + w3.toHex(node)[2:])

    # Get the merkle path for the commitment to spend
    mk_path_charlie_withdraw = zethUtils.compute_merkle_path(cm_address2_bob_transfer, mk_tree_depth, mk_byte_tree)
    input_note_charlie_withdraw = zethGRPC.zethNoteObjFromParsed(json.loads(recovered_plaintext2))
    (cm_address1_charlie_withdraw, cm_address2_charlie_withdraw, new_mk_root_charlie_withdraw, ciphertext1_charlie_withdraw, ciphertext2_charlie_withdraw) = charlie_withdraw(mixer_instance, new_mk_root_bob_transfer, mk_path_charlie_withdraw, input_note_charlie_withdraw, cm_address2_bob_transfer, charlie_eth_address, keystore)

    print("Balances after Charlie's withdrawal: ")
    print_balances(bob_eth_address, alice_eth_address, charlie_eth_address, mixer_instance.address)

    # TODO: Do a dummy payment from Alice to Alice where sum inputs = 0 = sum outputs (payment that is only used to make noise)
