import json
import time
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

# Global variables for the tests
#
# Ethereum addresses
deployer_eth_address = w3.eth.accounts[0]
bob_eth_address = w3.eth.accounts[1]
alice_eth_address = w3.eth.accounts[2]
charlie_eth_address = w3.eth.accounts[3]
# Dummy note value in HEX
zero_wei_hex = "0000000000000000"
# Zeth addresses
keystore = zethMock.initTestKeystore()
# Depth of the merkle tree (need to match the one used in the cpp prover)
mk_tree_depth = 4

def get_proof_joinsplit_2by2(
        mk_root,
        input_note1,
        input_address1,
        mk_path1,
        input_note2,
        input_address2,
        mk_path2,
        sender_ask,
        recipient1_apk,
        recipient2_apk,
        output_note_value1,
        output_note_value2,
        public_in_value,
        public_out_value
    ):
    input_nullifier1 = zethGRPC.computeNullifier(input_note1, sender_ask)
    input_nullifier2 = zethGRPC.computeNullifier(input_note2, sender_ask)
    js_inputs = [
        zethGRPC.createJSInput(mk_path1, input_address1, input_note1, sender_ask, input_nullifier1),
        zethGRPC.createJSInput(mk_path2, input_address2, input_note2, sender_ask, input_nullifier2)
    ]

    output_note1 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), recipient1_apk, output_note_value1)
    output_note2 = zethGRPC.createZethNote(zethGRPC.noteRandomness(), recipient2_apk, output_note_value2)
    js_outputs = [
        output_note1,
        output_note2
    ]

    proof_input = zethGRPC.makeProofInputs(mk_root, js_inputs, js_outputs, public_in_value, public_out_value)
    proof_obj = zethGRPC.getProof(test_grpc_endpoint, proof_input)
    proof_json = zethGRPC.parseProof(proof_obj)

    # We return the zeth notes to be able to spend them later
    # and the proof used to create them
    return (output_note1, output_note2, proof_json)

def bob_deposit(mixer_instance, mk_root, bob_eth_address):
    print("=== Bob deposits 4 ETH for himself and splits his deposited funds into note1: 2ETH, note2: 2ETH ===")
    bob_apk = keystore["Bob"]["AddrPk"]["aPK"]
    bob_ask = keystore["Bob"]["AddrSk"]["aSK"]
    # Create the JoinSplit dummy inputs for the deposit
    (input_note1, input_nullifier1, input_address1) = zethMock.getDummyInput(bob_apk, bob_ask)
    (input_note2, input_nullifier2, input_address2) = zethMock.getDummyInput(bob_apk, bob_ask)
    dummy_mk_path = zethMock.getDummyMerklePath(mk_tree_depth)

    (output_note1, output_note2, proof_json) = get_proof_joinsplit_2by2(
        mk_root,
        input_note1,
        input_address1,
        dummy_mk_path,
        input_note2,
        input_address2,
        dummy_mk_path,
        bob_ask, # sender
        bob_apk, # recipient1
        bob_apk, # recipient2
        zethGRPC.int64ToHexadecimal(Web3.toWei('2', 'ether')), # value output note 1
        zethGRPC.int64ToHexadecimal(Web3.toWei('2', 'ether')), # value output note 2
        zethGRPC.int64ToHexadecimal(Web3.toWei('4', 'ether')), # v_in
        zero_wei_hex # v_out
    )

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

def bob_to_charlie(mixer_instance, mk_root, mk_path1, input_note1, input_address1, bob_eth_address):
    print("=== Bob transfers 1ETH to Charlie from his funds on the mixer ===")

    charlie_apk = keystore["Charlie"]["AddrPk"]["aPK"] # We generate a coin for Charlie (recipient1)
    bob_apk = keystore["Bob"]["AddrPk"]["aPK"] # We generate a coin for Bob: the change (recipient2)
    bob_ask = keystore["Bob"]["AddrSk"]["aSK"] # Bob is the sender

    # Create the an additional dummy input for the JoinSplit
    (input_note2, input_nullifier2, input_address2) = zethMock.getDummyInput(bob_apk, bob_ask)
    dummy_mk_path = zethMock.getDummyMerklePath(mk_tree_depth)

    (output_note1, output_note2, proof_json) = get_proof_joinsplit_2by2(
        mk_root,
        input_note1,
        input_address1,
        mk_path1,
        input_note2,
        input_address2,
        dummy_mk_path,
        bob_ask, # sender
        bob_apk, # recipient1 (change)
        charlie_apk, # recipient2 (transfer)
        zethGRPC.int64ToHexadecimal(Web3.toWei('1', 'ether')), # value output note 1
        zethGRPC.int64ToHexadecimal(Web3.toWei('1', 'ether')), # value output note 2
        zero_wei_hex, # v_in
        zero_wei_hex # v_out
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

def charlie_withdraw(mixer_instance, mk_root, mk_path1, input_note1, input_address1, charlie_eth_address):
    print(" === Charlie withdraws 0.9 from his funds on the Mixer ===")

    charlie_apk = keystore["Charlie"]["AddrPk"]["aPK"]
    charlie_ask = keystore["Charlie"]["AddrSk"]["aSK"]

    # Create the an additional dummy input for the JoinSplit
    (input_note2, input_nullifier2, input_address2) = zethMock.getDummyInput(charlie_apk, charlie_ask)
    dummy_mk_path = zethMock.getDummyMerklePath(mk_tree_depth)

    (output_note1, output_note2, proof_json) = get_proof_joinsplit_2by2(
        mk_root,
        input_note1,
        input_address1,
        mk_path1,
        input_note2,
        input_address2,
        dummy_mk_path,
        charlie_ask, # sender
        charlie_apk, # recipient1
        charlie_apk, # recipient2
        zethGRPC.int64ToHexadecimal(Web3.toWei('0.1', 'ether')), # value output note 1
        zero_wei_hex, # value output note 2
        zero_wei_hex, # v_in
        zethGRPC.int64ToHexadecimal(Web3.toWei('0.9', 'ether')), # v_out
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

def receive(ciphertext, decryption_key, username):
    recovered_plaintext = ""
    try:
        recovered_plaintext = zethUtils.decrypt(ciphertext, decryption_key)
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

def get_merkle_tree(mixer_instance):
    mk_byte_tree = mixer_instance.functions.getTree().call()
    print("[DEBUG] Displaying the Merkle tree of commitments: ")
    for node in mk_byte_tree:
        print("Node: " + w3.toHex(node)[2:])
    return mk_byte_tree

if __name__ == '__main__':
    print("[INFO] 1. Fetching the verification key from the proving server")
    vk = zethGRPC.getVerificationKey(test_grpc_endpoint)

    print("[INFO] 2. Received VK, writing the key...")
    zethGRPC.writeVerificationKey(vk)

    print("[INFO] 3. VK written, deploying the smart contracts...")
    (verifier_interface, mixer_interface) = zethContracts.compile_contracts()
    (mixer_instance, initial_root) = zethContracts.deploy(
        mk_tree_depth,
        verifier_interface,
        mixer_interface,
        deployer_eth_address,
        4000000,
        "0x0000000000000000000000000000000000000000"
    )

    print("[INFO] 4. Running tests...")
    print("- Initial balances: ")
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Bob deposits 4ETH split in 2 notes of denominations of 2ETh and 2ETH on the mixer
    result_deposit_bob_to_bob = bob_deposit(mixer_instance, initial_root, bob_eth_address)
    cm_address_bob_to_bob1 = result_deposit_bob_to_bob[0]
    cm_address_bob_to_bob2 = result_deposit_bob_to_bob[1]
    new_merkle_root_bob_to_bob = result_deposit_bob_to_bob[2]
    ciphertext_bob_to_bob1 = result_deposit_bob_to_bob[3]
    ciphertext_bob_to_bob2 = result_deposit_bob_to_bob[4]

    print("- Balances after Bob's deposit: ")
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Alice sees a deposit and tries to decrypt the ciphertexts to see if she was the recipient
    # But she wasn't the recipient (Bob was), so she fails to decrypt
    recovered_plaintext1 = receive(ciphertext_bob_to_bob1, keystore["Alice"]["AddrSk"]["dk"], "alice")
    recovered_plaintext2 = receive(ciphertext_bob_to_bob2, keystore["Alice"]["AddrSk"]["dk"], "alice")
    assert (recovered_plaintext1 == ""),"Alice managed to decrypt a ciphertext that was not encrypted with her key!"
    assert (recovered_plaintext2 == ""),"Alice managed to decrypt a ciphertext that was not encrypted with her key!"

    # Bob does a transfer of 1ETH to Charlie on the mixer
    #
    # Bob looks in the merkle tree and gets the merkle path to the commitment he wants to spend
    mk_byte_tree = get_merkle_tree(mixer_instance)
    mk_path = zethUtils.compute_merkle_path(cm_address_bob_to_bob1, mk_tree_depth, mk_byte_tree)
    # Bob decrypts one of the note he previously received (useless here but useful if the payment came from someone else)
    input_note_json = json.loads(zethUtils.decrypt(ciphertext_bob_to_bob1, keystore["Bob"]["AddrSk"]["dk"]))
    input_note_bob_to_charlie = zethGRPC.zethNoteObjFromParsed(input_note_json)
    # Execution of the transfer
    result_transfer_bob_to_charlie = bob_to_charlie(
        mixer_instance,
        new_merkle_root_bob_to_bob,
        mk_path,
        input_note_bob_to_charlie,
        cm_address_bob_to_bob1,
        bob_eth_address
    )
    cm_address_bob_to_charlie1 = result_transfer_bob_to_charlie[0] # Bob -> Bob (Change)
    cm_address_bob_to_charlie2 = result_transfer_bob_to_charlie[1] # Bob -> Charlie (payment to Charlie)
    new_merkle_root_bob_to_charlie = result_transfer_bob_to_charlie[2]
    ciphertext_bob_to_charlie1 = result_transfer_bob_to_charlie[3]
    ciphertext_bob_to_charlie2 = result_transfer_bob_to_charlie[4]
    # Bob tries to do spend `input_note_bob_to_charlie` twice
    result_double_spending = ""
    try:
        result_double_spending = bob_to_charlie(
            mixer_instance,
            new_merkle_root_bob_to_bob,
            mk_path,
            input_note_bob_to_charlie,
            cm_address_bob_to_bob1,
            bob_eth_address
        )
    except:
        print("Bob's double spending successfully rejected")
    assert (result_double_spending == ""),"Bob managed to spend the same note twice!"

    print("Balances after Bob's transfer to Charlie: ")
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Charlie tries to decrypt the ciphertexts from Bob's previous transaction
    recovered_plaintext1 = receive(ciphertext_bob_to_charlie1, keystore["Charlie"]["AddrSk"]["dk"], "charlie")
    recovered_plaintext2 = receive(ciphertext_bob_to_charlie2, keystore["Charlie"]["AddrSk"]["dk"], "charlie")
    assert (recovered_plaintext1 == ""),"Charlie managed to decrypt a ciphertext that was not encrypted with his key!"
    assert (recovered_plaintext2 != ""),"Charlie should have been able to decrypt the ciphertext that was obtained with his key!"

    # Charlie now gets the merkle path for the commitment he wants to spend
    mk_byte_tree = get_merkle_tree(mixer_instance)
    mk_path = zethUtils.compute_merkle_path(cm_address_bob_to_charlie2, mk_tree_depth, mk_byte_tree)
    input_note_charlie_withdraw = zethGRPC.zethNoteObjFromParsed(json.loads(recovered_plaintext2))
    result_charlie_withdrawal = charlie_withdraw(
        mixer_instance,
        new_merkle_root_bob_to_charlie,
        mk_path,
        input_note_charlie_withdraw,
        cm_address_bob_to_charlie2,
        charlie_eth_address
    )

    print("Balances after Charlie's withdrawal: ")
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )
