#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import zeth.core.constants
import zeth.core.contracts
import zeth.core.merkle_tree
import zeth.core.utils
import zeth.core.zksnark
from zeth.core.prover_client import ProverClient
from zeth.core.zeth_address import ZethAddressPriv
from zeth.core.contracts import MixOutputEvents
from zeth.core.mixer_client import MixerClient
from zeth.core.wallet import Wallet, ZethNoteDescription
import test_commands.mock as mock
import test_commands.scenario as scenario

from os.path import join, exists
import shutil
from typing import Dict, List, Any


def print_balances(
        web3: Any, bob: str, alice: str, charlie: str, mixer: str) -> None:
    print("BALANCES:")
    print(f"  Alice   : {web3.eth.getBalance(alice)}")
    print(f"  Bob     : {web3.eth.getBalance(bob)}")
    print(f"  Charlie : {web3.eth.getBalance(charlie)}")
    print(f"  Mixer   : {web3.eth.getBalance(mixer)}")


def main() -> None:
    zksnark = zeth.core.zksnark.get_zksnark_provider(
        zeth.core.utils.parse_zksnark_arg())

    web3, eth = mock.open_test_web3()

    # Zeth addresses
    keystore = mock.init_test_keystore()
    # Ethereum addresses
    deployer_eth_address = eth.accounts[0]
    bob_eth_address = eth.accounts[1]
    alice_eth_address = eth.accounts[2]
    charlie_eth_address = eth.accounts[3]

    # ProverClient
    prover_client = ProverClient(mock.TEST_PROVER_SERVER_ENDPOINT)

    # Deploy Zeth contracts
    tree_depth = zeth.core.constants.ZETH_MERKLE_TREE_DEPTH
    zeth_client, _contract_desc = MixerClient.deploy(
        web3,
        prover_client,
        deployer_eth_address,
        None,
        None,
        None,
        zksnark)

    # Set up Merkle tree and Wallets. Note that each wallet holds an internal
    # Merkle Tree, unused in this test. Instead, we keep an in-memory version
    # shared by all virtual users. This avoids having to pass all mix results
    # to all wallets, and allows some of the methods in the scenario module,
    # which must update the tree directly.
    mk_tree = zeth.core.merkle_tree.MerkleTree.empty_with_depth(tree_depth)
    mixer_instance = zeth_client.mixer_instance

    # Keys and wallets
    def _mk_wallet(name: str, sk: ZethAddressPriv) -> Wallet:
        wallet_dir = join(mock.TEST_NOTE_DIR, name + "-eth")
        if exists(wallet_dir):
            # Note: symlink-attack resistance
            #   https://docs.python.org/3/library/shutil.html#shutil.rmtree.avoids_symlink_attacks
            shutil.rmtree(wallet_dir)
        return Wallet(mixer_instance, name, wallet_dir, sk)

    sk_alice = keystore['Alice'].addr_sk
    sk_bob = keystore['Bob'].addr_sk
    sk_charlie = keystore['Charlie'].addr_sk
    alice_wallet = _mk_wallet('alice', sk_alice)
    bob_wallet = _mk_wallet('bob', sk_bob)
    charlie_wallet = _mk_wallet('charlie', sk_charlie)
    block_num = 1

    # Universal update function
    def _receive_notes(
            out_ev: List[MixOutputEvents]) \
            -> Dict[str, List[ZethNoteDescription]]:
        nonlocal block_num
        notes = {
            'alice': alice_wallet.receive_notes(out_ev),
            'bob': bob_wallet.receive_notes(out_ev),
            'charlie': charlie_wallet.receive_notes(out_ev),
        }
        alice_wallet.update_and_save_state(block_num)
        bob_wallet.update_and_save_state(block_num)
        charlie_wallet.update_and_save_state(block_num)
        block_num = block_num + 1
        return notes

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
    recovered_notes = _receive_notes(result_deposit_bob_to_bob.output_events)
    assert(len(recovered_notes['alice']) == 0), \
        "Alice decrypted a ciphertext that was not encrypted with her key!"

    # Bob does a transfer to Charlie on the mixer

    # Bob decrypts one of the note he previously received (useless here but
    # useful if the payment came from someone else)
    assert(len(recovered_notes['bob']) == 2), \
        f"Bob recovered {len(recovered_notes['bob'])} notes, expected 2"

    # Execution of the transfer
    result_transfer_bob_to_charlie = scenario.bob_to_charlie(
        zeth_client,
        mk_tree,
        recovered_notes['bob'][0].as_input(),
        bob_eth_address,
        keystore)

    # Bob tries to spend `input_note_bob_to_charlie` twice
    result_double_spending = None
    try:
        result_double_spending = scenario.bob_to_charlie(
            zeth_client,
            mk_tree,
            recovered_notes['bob'][0].as_input(),
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
    recovered_notes = _receive_notes(
        result_transfer_bob_to_charlie.output_events)
    notes_charlie = recovered_notes['charlie']
    assert(len(notes_charlie) == 1), \
        f"Charlie decrypted {len(notes_charlie)}.  Expected 1!"

    input_charlie_withdraw = notes_charlie[0]

    charlie_balance_before_withdrawal = eth.getBalance(charlie_eth_address)
    _ = scenario.charlie_withdraw(
        zeth_client,
        mk_tree,
        input_charlie_withdraw.as_input(),
        charlie_eth_address,
        keystore)
    charlie_balance_after_withdrawal = eth.getBalance(charlie_eth_address)
    print("Balances after Charlie's withdrawal: ")
    print_balances(
        web3,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address)
    if charlie_balance_after_withdrawal <= charlie_balance_before_withdrawal:
        raise Exception("Charlie's balance did not increase after withdrawal")

    # Charlie tries to double-spend by withdrawing twice the same note
    result_double_spending = None
    try:
        # New commitments are added in the tree at each withdraw so we
        # recompiute the path to have the updated nodes
        result_double_spending = scenario.charlie_double_withdraw(
            zksnark,
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
        zksnark,
        zeth_client,
        mk_tree,
        bob_eth_address,
        charlie_eth_address,
        keystore)

    # Bob decrypts one of the note he previously received (should fail if
    # Charlie's attack succeeded)
    recovered_notes = _receive_notes(
        result_deposit_bob_to_bob.output_events)
    assert(len(recovered_notes['bob']) == 2), \
        f"Bob recovered {len(recovered_notes['bob'])} notes, expected 2"

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
