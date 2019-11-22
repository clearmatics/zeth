#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import zeth.contracts
import zeth.joinsplit
import zeth.zksnark
import zeth.utils
import zeth.constants as constants
import test_commands.mock as mock
import test_commands.scenario as scenario
from zeth.prover_client import ProverClient
from zeth.wallet import Wallet

import os
from web3 import Web3, HTTPProvider  # type: ignore

W3 = Web3(HTTPProvider(constants.WEB3_HTTP_PROVIDER))
eth = W3.eth  # pylint: disable=no-member,invalid-name
TEST_GRPC_ENDPOINT = constants.PROVER_SERVER_RPC_ENDPOINT


def print_balances(bob: str, alice: str, charlie: str, mixer: str) -> None:
    print("BALANCES:")
    print(f"  Alice   : {eth.getBalance(alice)}")
    print(f"  Bob     : {eth.getBalance(bob)}")
    print(f"  Charlie : {eth.getBalance(charlie)}")
    print(f"  Mixer   : {eth.getBalance(mixer)}")


def main() -> None:
    zksnark = zeth.zksnark.get_zksnark_provider(zeth.utils.parse_zksnark_arg())

    # Zeth addresses
    keystore = mock.init_test_keystore()
    # Ethereum addresses
    deployer_eth_address = eth.accounts[0]
    bob_eth_address = eth.accounts[1]
    alice_eth_address = eth.accounts[2]
    charlie_eth_address = eth.accounts[3]

    prover_client = ProverClient(TEST_GRPC_ENDPOINT)

    coinstore_dir = os.environ['ZETH_COINSTORE']

    # Keys and wallets
    k_sk_alice = keystore["Alice"].addr_sk.k_sk
    k_sk_bob = keystore["Bob"].addr_sk.k_sk
    k_sk_charlie = keystore["Charlie"].addr_sk.k_sk

    alice_wallet = Wallet("alice", coinstore_dir, k_sk_alice)
    bob_wallet = Wallet("bob", coinstore_dir, k_sk_bob)
    charlie_wallet = Wallet("charlie", coinstore_dir, k_sk_charlie)

    # Deploy Zeth contracts
    zeth_client = zeth.joinsplit.ZethClient.deploy(
        prover_client,
        constants.ZETH_MERKLE_TREE_DEPTH,
        deployer_eth_address,
        zksnark)

    print("[INFO] 4. Running tests (asset mixed: Ether)...")
    print("- Initial balances: ")
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address)

    # Bob deposits ETH, split in 2 notes on the mixer
    result_deposit_bob_to_bob = scenario.bob_deposit(
        zeth_client,
        bob_eth_address,
        keystore)

    print("- Balances after Bob's deposit: ")
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address
    )

    # Alice sees a deposit and tries to decrypt the ciphertexts to see if she
    # was the recipient but she wasn't the recipient (Bob was), so she fails to
    # decrypt
    recovered_notes_alice = alice_wallet.receive_notes(
        result_deposit_bob_to_bob.encrypted_notes,
        result_deposit_bob_to_bob.sender_k_pk)
    assert(len(recovered_notes_alice) == 0), \
        "Alice decrypted a ciphertext that was not encrypted with her key!"

    # Bob does a transfer to Charlie on the mixer

    # Bob decrypts one of the note he previously received (useless here but
    # useful if the payment came from someone else)
    recovered_notes_bob = bob_wallet.receive_notes(
        result_deposit_bob_to_bob.encrypted_notes,
        result_deposit_bob_to_bob.sender_k_pk)
    assert(len(recovered_notes_bob) == 2), \
        f"Bob recovered {len(recovered_notes_bob)} notes from deposit, expected 2"
    bob_to_charlie = recovered_notes_bob[0]

    # Execution of the transfer
    result_transfer_bob_to_charlie = scenario.bob_to_charlie(
        zeth_client,
        bob_to_charlie,
        bob_eth_address,
        keystore)

    # Bob tries to spend `input_note_bob_to_charlie` twice
    result_double_spending = None
    try:
        result_double_spending = scenario.bob_to_charlie(
            zeth_client,
            bob_to_charlie,
            bob_eth_address,
            keystore)
    except Exception as e:
        print(f"Bob's double spending successfully rejected! (msg: {e})")
    assert(result_double_spending is None), \
        "Bob managed to spend the same note twice!"

    print("- Balances after Bob's transfer to Charlie: ")
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address
    )

    # Charlie recovers his notes and attempts to withdraw them.
    notes_charlie = charlie_wallet.receive_notes(
        result_transfer_bob_to_charlie.encrypted_notes,
        result_transfer_bob_to_charlie.sender_k_pk)
    assert(len(notes_charlie) == 1), \
        f"Charlie decrypted {len(notes_charlie)}.  Expected 1!"

    input_charlie_withdraw = notes_charlie[0]
    assert input_charlie_withdraw[0] == \
        result_transfer_bob_to_charlie.encrypted_notes[1][0]

    _ = scenario.charlie_withdraw(
        zeth_client,
        input_charlie_withdraw,
        charlie_eth_address,
        keystore)
    print("Balances after Charlie's withdrawal: ")
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address)

    # Charlie tries to double-spend by withdrawing twice the same note
    result_double_spending = None
    try:
        # New commitments are added in the tree at each withdraw so we
        # recompiute the path to have the updated nodes
        result_double_spending = scenario.charlie_double_withdraw(
            zeth_client,
            input_charlie_withdraw,
            charlie_eth_address,
            keystore)
    except Exception as e:
        print(f"Charlie's double spending successfully rejected! (msg: {e})")
    print("Balances after Charlie's double withdrawal attempt: ")
    assert(result_double_spending is None), \
        "Charlie managed to withdraw the same note twice!"
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address)

    # Bob deposits once again ETH, split in 2 notes on the mixer
    # But Charlie attempts to corrupt the transaction (malleability attack)
    result_deposit_bob_to_bob = scenario.charlie_corrupt_bob_deposit(
        zeth_client,
        bob_eth_address,
        charlie_eth_address,
        keystore)

    # Bob decrypts one of the note he previously received (should fail if
    # Charlie's attack succeeded)
    recovered_notes_bob = bob_wallet.receive_notes(
        result_deposit_bob_to_bob.encrypted_notes,
        result_deposit_bob_to_bob.sender_k_pk)
    assert(len(recovered_notes_bob) == 2), \
        f"Bob recovered {len(recovered_notes_bob)} notes from deposit, expected 2"

    print("- Balances after Bob's last deposit: ")
    print_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address)

    print(
        "========================================\n" +
        "              TESTS PASSED\n" +
        "========================================\n")


if __name__ == '__main__':
    main()
