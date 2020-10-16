#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import zeth.core.merkle_tree
import zeth.core.utils
import zeth.core.constants as constants
from zeth.core.prover_client import ProverClient
from zeth.core.zeth_address import ZethAddressPriv
from zeth.core.contracts import MixOutputEvents
from zeth.core.mixer_client import MixerClient
from zeth.core.wallet import Wallet, ZethNoteDescription
from zeth.core.utils import EtherValue
import test_commands.mock as mock
import test_commands.scenario as scenario
from test_commands.deploy_test_token import deploy_token, mint_token
from os.path import join, exists
import shutil
from web3 import Web3  # type: ignore
from typing import Dict, List, Any


def print_token_balances(
        token_instance: Any,
        bob: str,
        alice: str,
        charlie: str,
        mixer: str) -> None:
    print("BALANCES:")
    print(f"  Alice   : {token_instance.functions.balanceOf(alice).call()}")
    print(f"  Bob     : {token_instance.functions.balanceOf(bob).call()}")
    print(f"  Charlie : {token_instance.functions.balanceOf(charlie).call()}")
    print(f"  Mixer   : {token_instance.functions.balanceOf(mixer).call()}")


def approve(
        token_instance: Any,
        owner_address: str,
        spender_address: str,
        token_amount: int) -> str:
    return token_instance.functions.approve(
        spender_address,
        Web3.toWei(token_amount, 'ether')).transact({'from': owner_address})


def allowance(
        token_instance: Any,
        owner_address: str,
        spender_address: str) -> str:
    return token_instance.functions.allowance(owner_address, spender_address) \
        .call()


def main() -> None:

    zksnark_name = zeth.core.utils.parse_zksnark_arg()
    zksnark = zeth.core.zksnark.get_zksnark_provider(zksnark_name)
    web3, eth = mock.open_test_web3()

    # Ethereum addresses
    deployer_eth_address = eth.accounts[0]
    bob_eth_address = eth.accounts[1]
    alice_eth_address = eth.accounts[2]
    charlie_eth_address = eth.accounts[3]
    # Zeth addresses
    keystore = mock.init_test_keystore()

    # Deploy the token contract
    token_instance = deploy_token(web3, deployer_eth_address, None, 4000000)

    # ProverClient
    prover_client = ProverClient(mock.TEST_PROVER_SERVER_ENDPOINT)
    assert prover_client.get_configuration().zksnark_name == zksnark_name

    # Deploy Zeth contracts
    tree_depth = constants.ZETH_MERKLE_TREE_DEPTH
    zeth_client, _contract_desc = MixerClient.deploy(
        web3,
        prover_client,
        deployer_eth_address,
        None,
        token_instance.address,
        None)
    mk_tree = zeth.core.merkle_tree.MerkleTree.empty_with_depth(tree_depth)
    mixer_instance = zeth_client.mixer_instance

    # Keys and wallets
    def _mk_wallet(name: str, sk: ZethAddressPriv) -> Wallet:
        wallet_dir = join(mock.TEST_NOTE_DIR, name + "-erc")
        if exists(wallet_dir):
            # Note: symlink-attack resistance
            #   https://docs.python.org/3/library/shutil.html#shutil.rmtree.avoids_symlink_attacks
            shutil.rmtree(wallet_dir)
        return Wallet(mixer_instance, name, wallet_dir, sk)
    sk_alice = keystore["Alice"].addr_sk
    sk_bob = keystore["Bob"].addr_sk
    sk_charlie = keystore["Charlie"].addr_sk
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

    print("[INFO] 4. Running tests (asset mixed: ERC20 token)...")
    # We assign ETHToken to Bob
    mint_token(
        web3,
        token_instance,
        bob_eth_address,
        deployer_eth_address,
        None,
        EtherValue(2*scenario.BOB_DEPOSIT_ETH, 'ether'))
    print("- Initial balances: ")
    print_token_balances(
        token_instance,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address)

    # Bob tries to deposit ETHToken, split in 2 notes on the mixer (without
    # approving)
    try:
        result_deposit_bob_to_bob = scenario.bob_deposit(
            zeth_client,
            mk_tree,
            bob_eth_address,
            keystore,
            zeth.core.utils.EtherValue(0))
    except Exception as e:
        allowance_mixer = allowance(
            token_instance,
            bob_eth_address,
            zeth_client.mixer_instance.address)
        print(f"[ERROR] Bob deposit failed! (msg: {e})")
        print("The allowance for Mixer from Bob is: ", allowance_mixer)

    # Bob approves the transfer
    print("- Bob approves the transfer of ETHToken to the Mixer")
    tx_hash = approve(
        token_instance,
        bob_eth_address,
        zeth_client.mixer_instance.address,
        scenario.BOB_DEPOSIT_ETH)
    eth.waitForTransactionReceipt(tx_hash)
    allowance_mixer = allowance(
        token_instance,
        bob_eth_address,
        zeth_client.mixer_instance.address)
    print("- The allowance for the Mixer from Bob is:", allowance_mixer)
    # Bob deposits ETHToken, split in 2 notes on the mixer
    result_deposit_bob_to_bob = scenario.bob_deposit(
        zeth_client, mk_tree, bob_eth_address, keystore)

    print("- Balances after Bob's deposit: ")
    print_token_balances(
        token_instance,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address
    )

    # Alice sees a deposit and tries to decrypt the ciphertexts to see if she
    # was the recipient, but Bob was the recipient so Alice fails to decrypt
    received_notes = _receive_notes(
        result_deposit_bob_to_bob.output_events)
    recovered_notes_alice = received_notes['alice']
    assert(len(recovered_notes_alice) == 0), \
        "Alice decrypted a ciphertext that was not encrypted with her key!"

    # Bob does a transfer of ETHToken to Charlie on the mixer

    # Bob decrypts one of the note he previously received (useless here but
    # useful if the payment came from someone else)
    recovered_notes_bob = received_notes['bob']
    assert(len(recovered_notes_bob) == 2), \
        f"Bob recovered {len(recovered_notes_bob)} notes from deposit, expected 2"
    input_bob_to_charlie = recovered_notes_bob[0].as_input()

    # Execution of the transfer
    result_transfer_bob_to_charlie = scenario.bob_to_charlie(
        zeth_client,
        mk_tree,
        input_bob_to_charlie,
        bob_eth_address,
        keystore)

    # Bob tries to spend `input_note_bob_to_charlie` twice
    result_double_spending = None
    try:
        result_double_spending = scenario.bob_to_charlie(
            zeth_client,
            mk_tree,
            input_bob_to_charlie,
            bob_eth_address,
            keystore)
    except Exception as e:
        print(f"Bob's double spending successfully rejected! (msg: {e})")
    assert(result_double_spending is None), "Bob spent the same note twice!"

    print("- Balances after Bob's transfer to Charlie: ")
    print_token_balances(
        token_instance,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address
    )

    # Charlie tries to decrypt the notes from Bob's previous transaction.
    received_notes = _receive_notes(
        result_transfer_bob_to_charlie.output_events)
    note_descs_charlie = received_notes['charlie']
    assert(len(note_descs_charlie) == 1), \
        f"Charlie decrypted {len(note_descs_charlie)}.  Expected 1!"

    _ = scenario.charlie_withdraw(
        zeth_client,
        mk_tree,
        note_descs_charlie[0].as_input(),
        charlie_eth_address,
        keystore)

    print("- Balances after Charlie's withdrawal: ")
    print_token_balances(
        token_instance,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address
    )

    # Charlie tries to carry out a double spend by withdrawing twice the same
    # note
    result_double_spending = None
    try:
        # New commitments are added in the tree at each withdraw so we
        # recompute the path to have the updated nodes
        result_double_spending = scenario.charlie_double_withdraw(
            zksnark,
            zeth_client,
            mk_tree,
            note_descs_charlie[0].as_input(),
            charlie_eth_address,
            keystore)
    except Exception as e:
        print(f"Charlie's double spending successfully rejected! (msg: {e})")
    print("Balances after Charlie's double withdrawal attempt: ")
    assert(result_double_spending is None), \
        "Charlie managed to withdraw the same note twice!"
    print_token_balances(
        token_instance,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        zeth_client.mixer_instance.address)

    # Bob deposits once again ETH, split in 2 notes on the mixer
    # But Charlie attempts to corrupt the transaction (malleability attack)

    # Bob approves the transfer
    print("- Bob approves the transfer of ETHToken to the Mixer")
    tx_hash = approve(
        token_instance,
        bob_eth_address,
        zeth_client.mixer_instance.address,
        scenario.BOB_DEPOSIT_ETH)
    eth.waitForTransactionReceipt(tx_hash)
    allowance_mixer = allowance(
        token_instance,
        bob_eth_address,
        zeth_client.mixer_instance.address)
    print("- The allowance for the Mixer from Bob is:", allowance_mixer)

    result_deposit_bob_to_bob = scenario.charlie_corrupt_bob_deposit(
        zksnark,
        zeth_client,
        mk_tree,
        bob_eth_address,
        charlie_eth_address,
        keystore)

    # Bob decrypts one of the note he previously received (should fail if
    # Charlie's attack succeeded)
    received_notes = _receive_notes(
        result_deposit_bob_to_bob.output_events)
    recovered_notes_bob = received_notes['bob']
    assert(len(recovered_notes_bob) == 2), \
        f"Bob recovered {len(recovered_notes_bob)} notes from deposit, expected 2"

    print("- Balances after Bob's last deposit: ")
    print_token_balances(
        token_instance,
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
