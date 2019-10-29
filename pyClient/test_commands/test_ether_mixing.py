import json
from web3 import Web3, HTTPProvider  # type: ignore

import zeth.contracts
import zeth.grpc
import zeth.utils
import zeth.constants as constants
import test_commands.mock as mock
import test_commands.scenario as scenario

w3 = Web3(HTTPProvider(constants.WEB3_HTTP_PROVIDER))
test_grpc_endpoint = constants.RPC_ENDPOINT


def print_balances(bob, alice, charlie, mixer):
    print("Bob's ETH balance: ", w3.eth.getBalance(bob))
    print("Alice's ETH balance: ", w3.eth.getBalance(alice))
    print("Charlie's ETH balance: ", w3.eth.getBalance(charlie))
    print("Mixer's ETH balance: ", w3.eth.getBalance(mixer))


def get_merkle_tree(mixer_instance):
    mk_byte_tree = mixer_instance.functions.getTree().call()
    print("[DEBUG] Displaying the Merkle tree of commitments: ")
    for node in mk_byte_tree:
        print("Node: " + w3.toHex(node)[2:])
    return mk_byte_tree


def main():
    zksnark = zeth.utils.parse_zksnark_arg()

    # Zeth addresses
    keystore = mock.initTestKeystore()
    # Depth of the merkle tree (need to match the one used in the cpp prover)
    mk_tree_depth = constants.ZETH_MERKLE_TREE_DEPTH
    # Ethereum addresses
    deployer_eth_address = w3.eth.accounts[0]
    bob_eth_address = w3.eth.accounts[1]
    alice_eth_address = w3.eth.accounts[2]
    charlie_eth_address = w3.eth.accounts[3]

    print("[INFO] 1. Fetching the verification key from the proving server")
    vk = zeth.grpc.getVerificationKey(test_grpc_endpoint)

    print("[INFO] 2. Received VK, writing the key...")
    zeth.grpc.writeVerificationKey(vk, zksnark)

    print("[INFO] 3. VK written, deploying the smart contracts...")
    (proof_verifier_interface, otsig_verifier_interface, mixer_interface) = \
        zeth.contracts.compile_contracts(zksnark)
    hasher_interface, _ = zeth.contracts.compile_util_contracts()
    (mixer_instance, initial_root) = zeth.contracts.deploy_contracts(
        mk_tree_depth,
        proof_verifier_interface,
        otsig_verifier_interface,
        mixer_interface,
        hasher_interface,
        deployer_eth_address,
        4000000,
        # We mix Ether in this test, so we set the addr of the ERC20 contract
        # to be 0x0
        "0x0000000000000000000000000000000000000000",
        zksnark
    )

    print("[INFO] 4. Running tests (asset mixed: Ether)...")
    print("- Initial balances: ")
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Bob deposits ETH, split in 2 notes on the mixer
    result_deposit_bob_to_bob = scenario.bob_deposit(
        test_grpc_endpoint,
        mixer_instance,
        initial_root,
        bob_eth_address,
        keystore,
        mk_tree_depth,
        zksnark
    )
    cm_address_bob_to_bob1 = result_deposit_bob_to_bob[0]
    # cm_address_bob_to_bob2 = result_deposit_bob_to_bob[1]   # Unused
    new_merkle_root_bob_to_bob = result_deposit_bob_to_bob[2]
    pk_sender_ciphertext_bob_to_bob = result_deposit_bob_to_bob[3]
    ciphertext_bob_to_bob1 = result_deposit_bob_to_bob[4]
    ciphertext_bob_to_bob2 = result_deposit_bob_to_bob[5]

    print("- Balances after Bob's deposit: ")
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Construct sk and pk objects from bytes
    sk_alice = zeth.utils.get_private_key_from_bytes(
        keystore["Alice"]["AddrSk"]["encSK"])
    pk_sender = zeth.utils.get_public_key_from_bytes(
        pk_sender_ciphertext_bob_to_bob)

    # Alice sees a deposit and tries to decrypt the ciphertexts to see if she
    # was the recipient but she wasn't the recipient (Bob was), so she fails to
    # decrypt
    recovered_plaintext1 = zeth.utils.receive(
        ciphertext_bob_to_bob1, pk_sender, sk_alice, "alice")
    recovered_plaintext2 = zeth.utils.receive(
        ciphertext_bob_to_bob2, pk_sender, sk_alice, "alice")
    assert(recovered_plaintext1 == ""), \
        "Alice decrypted a ciphertext that was not encrypted with her key!"
    assert(recovered_plaintext2 == ""),\
        "Alice decrypted a ciphertext that was not encrypted with her key!"
    # Alice sees a deposit and tries to decrypt the ciphertexts to see if she
    # was the recipient but she wasn't the recipient (Bob was), so she fails to
    # decrypt
    recovered_plaintext1 = zeth.utils.receive(
        ciphertext_bob_to_bob1, pk_sender, sk_alice, "alice")
    recovered_plaintext2 = zeth.utils.receive(
        ciphertext_bob_to_bob2, pk_sender, sk_alice, "alice")
    assert(recovered_plaintext1 == ""), \
        "Alice decrypted a ciphertext that was not encrypted with her key!"
    assert(recovered_plaintext2 == ""),\
        "Alice decrypted a ciphertext that was not encrypted with her key!"

    # Bob does a transfer to Charlie on the mixer
    #
    # Bob looks in the merkle tree and gets the merkle path to the commitment
    # he wants to spend
    mk_byte_tree = get_merkle_tree(mixer_instance)
    mk_path = zeth.utils.compute_merkle_path(
        cm_address_bob_to_bob1, mk_tree_depth, mk_byte_tree)

    # Bob decrypts one of the note he previously received (useless here but
    # useful if the payment came from someone else)
    sk_bob = zeth.utils.get_private_key_from_bytes(
        keystore["Bob"]["AddrSk"]["encSK"])
    input_note_json = json.loads(
        zeth.utils.decrypt(ciphertext_bob_to_bob1, pk_sender, sk_bob))
    input_note_bob_to_charlie = zeth.grpc.zethNoteObjFromParsed(input_note_json)
    # Execution of the transfer
    result_transfer_bob_to_charlie = scenario.bob_to_charlie(
        test_grpc_endpoint,
        mixer_instance,
        new_merkle_root_bob_to_bob,
        mk_path,
        input_note_bob_to_charlie,
        cm_address_bob_to_bob1,
        bob_eth_address,
        keystore,
        mk_tree_depth,
        zksnark
    )

    # Bob -> Bob (Change - unused)
    # cm_address_bob_to_charlie1 = result_transfer_bob_to_charlie[0]
    # Bob -> Charlie (payment to Charlie)
    cm_address_bob_to_charlie2 = result_transfer_bob_to_charlie[1]
    new_merkle_root_bob_to_charlie = result_transfer_bob_to_charlie[2]
    pk_sender_ciphertext_bob_to_charlie = result_transfer_bob_to_charlie[3]
    ciphertext_bob_to_charlie1 = result_transfer_bob_to_charlie[4]
    ciphertext_bob_to_charlie2 = result_transfer_bob_to_charlie[5]

    # Bob tries to spend `input_note_bob_to_charlie` twice
    result_double_spending = ""
    try:
        result_double_spending = scenario.bob_to_charlie(
            test_grpc_endpoint,
            mixer_instance,
            new_merkle_root_bob_to_bob,
            mk_path,
            input_note_bob_to_charlie,
            cm_address_bob_to_bob1,
            bob_eth_address,
            keystore,
            mk_tree_depth,
            zksnark
        )
    except Exception as e:
        print(f"Bob's double spending successfully rejected! (msg: {e})")
    assert(result_double_spending == ""), \
        "Bob managed to spend the same note twice!"

    print("- Balances after Bob's transfer to Charlie: ")
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Construct sk and pk objects from bytes
    sk_charlie = zeth.utils.get_private_key_from_bytes(
        keystore["Charlie"]["AddrSk"]["encSK"])
    pk_sender = zeth.utils.get_public_key_from_bytes(
        pk_sender_ciphertext_bob_to_charlie)

    # Charlie tries to decrypt the ciphertexts from Bob's previous transaction
    recovered_plaintext1 = zeth.utils.receive(
        ciphertext_bob_to_charlie1, pk_sender, sk_charlie, "charlie")
    recovered_plaintext2 = zeth.utils.receive(
        ciphertext_bob_to_charlie2, pk_sender, sk_charlie, "charlie")
    assert(recovered_plaintext1 == ""), \
        "Charlie decrypted a ciphertext that was not encrypted with his key!"
    assert(recovered_plaintext2 != ""), \
        "Charlie was unable to decrypt the ciphertext obtained with his key!"

    # Charlie now gets the merkle path for the commitment he wants to spend
    mk_byte_tree = get_merkle_tree(mixer_instance)
    mk_path = zeth.utils.compute_merkle_path(
        cm_address_bob_to_charlie2, mk_tree_depth, mk_byte_tree)
    input_note_charlie_withdraw = zeth.grpc.zethNoteObjFromParsed(
        json.loads(recovered_plaintext2))
    result_charlie_withdrawal = scenario.charlie_withdraw(
        test_grpc_endpoint,
        mixer_instance,
        new_merkle_root_bob_to_charlie,
        mk_path,
        input_note_charlie_withdraw,
        cm_address_bob_to_charlie2,
        charlie_eth_address,
        keystore,
        mk_tree_depth,
        zksnark
    )
    new_merkle_root_charlie_withdrawal = result_charlie_withdrawal[2]
    print("Balances after Charlie's withdrawal: ")
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Charlie tries to double-spend by withdrawing twice the same note
    result_double_spending = ""
    try:
        # New commitments are added in the tree at each withdraw so we
        # recompiute the path to have the updated nodes
        mk_byte_tree = get_merkle_tree(mixer_instance)
        mk_path = zeth.utils.compute_merkle_path(
            cm_address_bob_to_charlie2, mk_tree_depth, mk_byte_tree)
        result_double_spending = scenario.charlie_double_withdraw(
            test_grpc_endpoint,
            mixer_instance,
            new_merkle_root_charlie_withdrawal,
            mk_path,
            input_note_charlie_withdraw,
            cm_address_bob_to_charlie2,
            charlie_eth_address,
            keystore,
            mk_tree_depth,
            zksnark
        )
    except Exception as e:
        print(f"Charlie's double spending successfully rejected! (msg: {e})")
    print("Balances after Charlie's double withdrawal attempt: ")
    assert(result_double_spending == ""), \
        "Charlie managed to withdraw the same note twice!"
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )


if __name__ == '__main__':
    main()
