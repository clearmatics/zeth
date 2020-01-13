#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import zeth.contracts
import zeth.joinsplit
import zeth.merkle_tree
import zeth.zksnark
import zeth.utils
import zeth.constants as constants
import test_commands.mock as mock
import test_commands.scenario as scenario
from zeth.wallet import Wallet

import os
from typing import Any
# from web3 import Web3, HTTPProvider  # type: ignore


def print_balances(
        web3: Any, bob: str, alice: str, charlie: str, mixer: str) -> None:
    print("BALANCES:")
    print(f"  Alice   : {web3.eth.getBalance(alice)}")
    print(f"  Bob     : {web3.eth.getBalance(bob)}")
    print(f"  Charlie : {web3.eth.getBalance(charlie)}")
    print(f"  Mixer   : {web3.eth.getBalance(mixer)}")


def main() -> None:
    zksnark = zeth.zksnark.get_zksnark_provider(zeth.utils.parse_zksnark_arg())

    web3, eth = mock.open_test_web3()

    # Zeth addresses
    keystore = mock.init_test_keystore()
    # Ethereum addresses
    deployer_eth_address = eth.accounts[0]
    bob_eth_address = eth.accounts[1]
    alice_eth_address = eth.accounts[2]
    charlie_eth_address = eth.accounts[3]

    prover_client = mock.open_test_prover_client()

    coinstore_dir = os.environ['ZETH_COINSTORE']

    # Deploy Zeth contracts
    tree_depth = constants.ZETH_MERKLE_TREE_DEPTH
    zeth_client = zeth.joinsplit.ZethClient.deploy(
        web3,
        prover_client,
        tree_depth,
        deployer_eth_address,
        zksnark)
    mk_tree = zeth.merkle_tree.MerkleTree.empty_with_depth(tree_depth)

    # Keys and wallets
    sk_alice = keystore["Alice"].addr_sk
    sk_bob = keystore["Bob"].addr_sk
    sk_charlie = keystore["Charlie"].addr_sk

    mixer_instance = zeth_client.mixer_instance
    alice_wallet = Wallet(mixer_instance, "alice", coinstore_dir, sk_alice)
    bob_wallet = Wallet(mixer_instance, "bob", coinstore_dir, sk_bob)
    charlie_wallet = Wallet(mixer_instance, "charlie", coinstore_dir, sk_charlie)

    print("[INFO] 4. Running tests (asset mixed: Ether)...")
    print("- Initial balances: ")
    print_balances(
        web3,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address)

    # Bob deposits ETH, split in 2 notes on the mixer
    result_deposit_bob_to_bob = scenario.bob_deposit(
        zeth_client,
        mk_tree,
        bob_eth_address,
        keystore)

    print("- Balances after Bob's deposit: ")
    print_balances(
        web3,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address
    )

    # Alice sees a deposit and tries to decrypt the ciphertexts to see if she
    # was the recipient but she wasn't the recipient (Bob was), so she fails to
    # decrypt
    recovered_notes_alice = alice_wallet.receive_notes(
        result_deposit_bob_to_bob.output_events,
        result_deposit_bob_to_bob.sender_k_pk)
    assert(len(recovered_notes_alice) == 0), \
        "Alice decrypted a ciphertext that was not encrypted with her key!"

    # Bob does a transfer to Charlie on the mixer

    # Bob decrypts one of the note he previously received (useless here but
    # useful if the payment came from someone else)
    recovered_notes_bob = bob_wallet.receive_notes(
        result_deposit_bob_to_bob.output_events,
        result_deposit_bob_to_bob.sender_k_pk)
    assert(len(recovered_notes_bob) == 2), \
        f"Bob recovered {len(recovered_notes_bob)} notes from deposit, expected 2"

    # Execution of the transfer
    result_transfer_bob_to_charlie = scenario.bob_to_charlie(
        zeth_client,
        mk_tree,
        recovered_notes_bob[0].as_input(),
        bob_eth_address,
        keystore)

    # Bob tries to spend `input_note_bob_to_charlie` twice
    result_double_spending = None
    try:
        result_double_spending = scenario.bob_to_charlie(
            zeth_client,
            mk_tree,
            recovered_notes_bob[0].as_input(),
            bob_eth_address,
            keystore)
    except Exception as e:
        print(f"Bob's double spending successfully rejected! (msg: {e})")
    assert(result_double_spending is None), \
        "Bob managed to spend the same note twice!"

    print("- Balances after Bob's transfer to Charlie: ")
    print_balances(
        web3,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address
    )

    # Charlie recovers his notes and attempts to withdraw them.
    notes_charlie = charlie_wallet.receive_notes(
        result_transfer_bob_to_charlie.output_events,
        result_transfer_bob_to_charlie.sender_k_pk)
    assert(len(notes_charlie) == 1), \
        f"Charlie decrypted {len(notes_charlie)}.  Expected 1!"

    input_charlie_withdraw = notes_charlie[0]
    assert notes_charlie[0].address == \
        result_transfer_bob_to_charlie.output_events[1].commitment_address

    _ = scenario.charlie_withdraw(
        zeth_client,
        mk_tree,
        input_charlie_withdraw.as_input(),
        charlie_eth_address,
        keystore)
    print("Balances after Charlie's withdrawal: ")
    print_balances(
        web3,
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
            mk_tree,
            input_charlie_withdraw.as_input(),
            charlie_eth_address,
            keystore)
    except Exception as e:
        print(f"Charlie's double spending successfully rejected! (msg: {e})")
    print("Balances after Charlie's double withdrawal attempt: ")
    assert(result_double_spending is None), \
        "Charlie managed to withdraw the same note twice!"
    print_balances(
        web3,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address)

    # Bob deposits once again ETH, split in 2 notes on the mixer
    # But Charlie attempts to corrupt the transaction (malleability attack)
    result_deposit_bob_to_bob = scenario.charlie_corrupt_bob_deposit(
        zeth_client,
        mk_tree,
        bob_eth_address,
        charlie_eth_address,
        keystore)

    # Bob decrypts one of the note he previously received (should fail if
    # Charlie's attack succeeded)
    recovered_notes_bob = bob_wallet.receive_notes(
        result_deposit_bob_to_bob.output_events,
        result_deposit_bob_to_bob.sender_k_pk)
    assert(len(recovered_notes_bob) == 2), \
        f"Bob recovered {len(recovered_notes_bob)} notes from deposit, expected 2"

    print("- Balances after Bob's last deposit: ")
    print_balances(
        web3,
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
