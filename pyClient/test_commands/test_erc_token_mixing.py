#!/usr/bin/env python3

import zeth.contracts as contracts
import zeth.joinsplit
import zeth.zksnark
from zeth.prover_client import ProverClient
from zeth.wallet import Wallet
import zeth.utils
import zeth.constants as constants
import test_commands.mock as mock
import test_commands.scenario as scenario

import os
from web3 import Web3, HTTPProvider  # type: ignore
from solcx import compile_files  # type: ignore
from os.path import join
from typing import Any

W3 = Web3(HTTPProvider(constants.WEB3_HTTP_PROVIDER))
eth = W3.eth  # pylint: disable=no-member,invalid-name
TEST_GRPC_ENDPOINT = constants.RPC_ENDPOINT


def compile_token() -> contracts.Interface:
    """
    Compile the testing ERC20 token contract
    """

    zeth_dir = zeth.utils.get_zeth_dir()
    allowed_path = join(
        zeth_dir,
        "zeth-contracts/node_modules/openzeppelin-solidity/contracts")
    path_to_token = os.path.join(
        zeth_dir,
        "zeth-contracts/node_modules/openzeppelin-solidity/contracts",
        "token/ERC20/ERC20Mintable.sol")
    # Compilation
    compiled_sol = compile_files([path_to_token], allow_paths=allowed_path)
    token_interface = compiled_sol[path_to_token + ":ERC20Mintable"]
    return token_interface


def deploy_token(
        deployer_address: str,
        deployment_gas: int) -> Any:
    """
    Deploy the testing ERC20 token contract
    """
    token_interface = compile_token()
    token = eth.contract(
        abi=token_interface['abi'], bytecode=token_interface['bin'])
    tx_hash = token.constructor().transact(
        {'from': deployer_address, 'gas': deployment_gas})
    tx_receipt = eth.waitForTransactionReceipt(tx_hash)

    token = eth.contract(
        address=tx_receipt.contractAddress,
        abi=token_interface['abi'],
    )
    return token


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
        W3.toWei(token_amount, 'ether')).transact({'from': owner_address})


def allowance(
        token_instance: Any,
        owner_address: str,
        spender_address: str) -> str:
    return token_instance.functions.allowance(owner_address, spender_address) \
        .call()


def mint_token(
        token_instance: Any,
        spender_address: str,
        deployer_address: str,
        token_amount: int) -> bytes:
    return token_instance.functions.mint(
        spender_address,
        W3.toWei(token_amount, 'ether')).transact({'from': deployer_address})


def main() -> None:
    zksnark = zeth.zksnark.get_zksnark_provider(zeth.utils.parse_zksnark_arg())

    # Ethereum addresses
    deployer_eth_address = eth.accounts[0]
    bob_eth_address = eth.accounts[1]
    alice_eth_address = eth.accounts[2]
    charlie_eth_address = eth.accounts[3]
    # Zeth addresses
    keystore = mock.init_test_keystore()
    # Depth of the merkle tree (need to match the one used in the cpp prover)
    mk_tree_depth = constants.ZETH_MERKLE_TREE_DEPTH

    prover_client = ProverClient(TEST_GRPC_ENDPOINT)

    coinstore_dir = os.environ['ZETH_COINSTORE']

    # Keys and wallets
    k_sk_alice = keystore["Alice"].addr_sk.k_sk
    k_sk_bob = keystore["Bob"].addr_sk.k_sk
    k_sk_charlie = keystore["Charlie"].addr_sk.k_sk

    alice_wallet = Wallet("alice", coinstore_dir, k_sk_alice)
    bob_wallet = Wallet("bob", coinstore_dir, k_sk_bob)
    charlie_wallet = Wallet("charlie", coinstore_dir, k_sk_charlie)

    print("[INFO] 1. Fetching the verification key from the proving server")
    vk = prover_client.get_verification_key()

    print("[INFO] 2. Received VK, writing the key...")
    zeth.joinsplit.write_verification_key(vk, zksnark)

    print("[INFO] 3. VK written, deploying the smart contracts...")
    (proof_verifier_interface, otsig_verifier_interface, mixer_interface) = \
        zeth.contracts.compile_contracts(zksnark)
    hasher_interface, _ = zeth.contracts.compile_util_contracts()
    token_instance = deploy_token(deployer_eth_address, 4000000)
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
        token_instance.address,
        zksnark
    )

    print("[INFO] 4. Running tests (asset mixed: ERC20 token)...")
    # We assign ETHToken to Bob
    mint_token(
        token_instance,
        bob_eth_address,
        deployer_eth_address,
        scenario.BOB_DEPOSIT_ETH)
    print("- Initial balances: ")
    print_token_balances(
        token_instance,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Bob tries to deposit ETHToken, split in 2 notes on the mixer (without
    # approving)
    try:
        result_deposit_bob_to_bob = scenario.bob_deposit(
            prover_client,
            mixer_instance,
            initial_root,
            bob_eth_address,
            keystore,
            mk_tree_depth,
            zksnark
        )
    except Exception as e:
        allowance_mixer = allowance(
            token_instance, bob_eth_address, mixer_instance.address)
        print(f"[ERROR] Bob deposit failed! (msg: {e})")
        print("The allowance for Mixer from Bob is: ", allowance_mixer)

    # Bob approves the transfer
    print("- Bob approves the transfer of ETHToken to the Mixer")
    tx_hash = approve(
        token_instance,
        bob_eth_address,
        mixer_instance.address,
        scenario.BOB_DEPOSIT_ETH)
    eth.waitForTransactionReceipt(tx_hash)
    allowance_mixer = allowance(
        token_instance, bob_eth_address, mixer_instance.address)
    print("- The allowance for the Mixer from Bob is:", allowance_mixer)
    # Bob deposits ETHToken, split in 2 notes on the mixer
    result_deposit_bob_to_bob = scenario.bob_deposit(
        prover_client,
        mixer_instance,
        initial_root,
        bob_eth_address,
        keystore,
        mk_tree_depth,
        zksnark
    )
    new_merkle_root_bob_to_bob = result_deposit_bob_to_bob.new_merkle_root

    print("- Balances after Bob's deposit: ")
    print_token_balances(
        token_instance,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Alice sees a deposit and tries to decrypt the ciphertexts to see if she
    # was the recipient, but Bob was the recipient so Alice fails to decrypt
    recovered_notes_alice = alice_wallet.receive_notes(
        result_deposit_bob_to_bob.encrypted_notes,
        result_deposit_bob_to_bob.sender_k_pk)
    assert(len(recovered_notes_alice) == 0), \
        "Alice decrypted a ciphertext that was not encrypted with her key!"

    # Bob does a transfer of ETHToken to Charlie on the mixer
    #
    # Bob looks in the merkle tree and gets the merkle path to the commitment
    # he wants to spend
    mk_byte_tree = contracts.get_merkle_tree(mixer_instance)
    mk_path = zeth.utils.compute_merkle_path(
        result_deposit_bob_to_bob.encrypted_notes[0][0],
        mk_tree_depth,
        mk_byte_tree)

    # Bob decrypts one of the note he previously received (useless here but
    # useful if the payment came from someone else)
    recovered_notes_bob = bob_wallet.receive_notes(
        result_deposit_bob_to_bob.encrypted_notes,
        result_deposit_bob_to_bob.sender_k_pk)
    assert(len(recovered_notes_bob) == 2), \
        f"Bob recovered {len(recovered_notes_bob)} notes from deposit, expected 2"
    input_bob_to_charlie = recovered_notes_bob[0]
    assert input_bob_to_charlie[0] == \
        result_deposit_bob_to_bob.encrypted_notes[0][0]

    # Execution of the transfer
    result_transfer_bob_to_charlie = scenario.bob_to_charlie(
        prover_client,
        mixer_instance,
        new_merkle_root_bob_to_bob,
        mk_path,
        input_bob_to_charlie,
        bob_eth_address,
        keystore,
        mk_tree_depth,
        zksnark
    )

    new_merkle_root_bob_to_charlie = \
        result_transfer_bob_to_charlie.new_merkle_root

    # Bob tries to spend `input_note_bob_to_charlie` twice
    result_double_spending = None
    try:
        result_double_spending = scenario.bob_to_charlie(
            prover_client,
            mixer_instance,
            new_merkle_root_bob_to_bob,
            mk_path,
            input_bob_to_charlie,
            bob_eth_address,
            keystore,
            mk_tree_depth,
            zksnark
        )
    except Exception as e:
        print(f"Bob's double spending successfully rejected! (msg: {e})")
    assert(result_double_spending is None), "Bob spent the same note twice!"

    print("- Balances after Bob's transfer to Charlie: ")
    print_token_balances(
        token_instance,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Charlie tries to decrypt the notes from Bob's previous transaction.
    notes_charlie = charlie_wallet.receive_notes(
        result_transfer_bob_to_charlie.encrypted_notes,
        result_transfer_bob_to_charlie.sender_k_pk)
    assert(len(notes_charlie) == 1), \
        f"Charlie decrypted {len(notes_charlie)}.  Expected 1!"

    # Charlie now gets the merkle path for the commitment he wants to spend
    mk_byte_tree = contracts.get_merkle_tree(mixer_instance)
    mk_path = zeth.utils.compute_merkle_path(
        notes_charlie[0][0], mk_tree_depth, mk_byte_tree)
    assert notes_charlie[0][0] == \
        result_transfer_bob_to_charlie.encrypted_notes[1][0]

    result_charlie_withdrawal = scenario.charlie_withdraw(
        prover_client,
        mixer_instance,
        new_merkle_root_bob_to_charlie,
        mk_path,
        notes_charlie[0],
        charlie_eth_address,
        keystore,
        mk_tree_depth,
        zksnark
    )

    new_merkle_root_charlie_withdrawal = \
        result_charlie_withdrawal.new_merkle_root
    print("- Balances after Charlie's withdrawal: ")
    print_token_balances(
        token_instance,
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Charlie tries to carry out a double spend by withdrawing twice the same
    # note
    result_double_spending = None
    try:
        # New commitments are added in the tree at each withdraw so we
        # recompiute the path to have the updated nodes
        mk_byte_tree = contracts.get_merkle_tree(mixer_instance)
        mk_path = zeth.utils.compute_merkle_path(
            notes_charlie[0][0], mk_tree_depth, mk_byte_tree)
        result_double_spending = scenario.charlie_double_withdraw(
            prover_client,
            mixer_instance,
            new_merkle_root_charlie_withdrawal,
            mk_path,
            notes_charlie[0],
            charlie_eth_address,
            keystore,
            mk_tree_depth,
            zksnark
        )
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
        mixer_instance.address
    )


if __name__ == '__main__':
    main()
