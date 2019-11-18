import zeth.joinsplit as joinsplit
import zeth.contracts as contracts
from zeth.prover_client import ProverClient
from zeth.zksnark import IZKSnarkProvider
from zeth.utils import to_zeth_units, int64_to_hex, compute_merkle_path
import test_commands.mock as mock
import api.util_pb2 as util_pb2

from web3 import Web3, HTTPProvider  # type: ignore
from typing import List, Tuple, Any

W3 = Web3(HTTPProvider("http://localhost:8545"))

ZERO_UNITS_HEX = "0000000000000000"
BOB_DEPOSIT_ETH = 200
BOB_SPLIT_1_ETH = 100
BOB_SPLIT_2_ETH = 100

BOB_TO_CHARLIE_ETH = 50
BOB_TO_CHARLIE_CHANGE_ETH = BOB_SPLIT_1_ETH - BOB_TO_CHARLIE_ETH

CHARLIE_WITHDRAW_ETH = 10.5
CHARLIE_WITHDRAW_CHANGE_ETH = 39.5


def dump_merkle_tree(mk_tree: List[bytes]) -> None:
    print("[DEBUG] Displaying the Merkle tree of commitments: ")
    for node in mk_tree:
        print("Node: " + W3.toHex(node)[2:])


def bob_deposit(
        prover_client: ProverClient,
        mixer_instance: Any,
        mk_root: str,
        bob_eth_address: str,
        keystore: mock.KeyStore,
        mk_tree_depth: int,
        zksnark: IZKSnarkProvider) -> contracts.MixResult:
    print(
        f"=== Bob deposits {BOB_DEPOSIT_ETH} ETH for himself and splits into " +
        f"note1: {BOB_SPLIT_1_ETH}ETH, note2: {BOB_SPLIT_2_ETH}ETH ===")

    bob_ask = keystore["Bob"].addr_sk.a_sk
    bob_addr = keystore["Bob"].addr_pk

    outputs = [
        (bob_addr, to_zeth_units(str(BOB_SPLIT_1_ETH), 'ether')),
        (bob_addr, to_zeth_units(str(BOB_SPLIT_2_ETH), 'ether')),
    ]

    mk_tree = contracts.get_merkle_tree(mixer_instance)
    return joinsplit.zeth_spend(
        prover_client,
        mixer_instance,
        mk_root,
        mk_tree,
        mk_tree_depth,
        zksnark,
        joinsplit.OwnershipKeyPair(bob_ask, bob_addr.a_pk),
        bob_eth_address,
        [],
        outputs,
        int64_to_hex(to_zeth_units(str(BOB_DEPOSIT_ETH), 'ether')),
        ZERO_UNITS_HEX,
        W3.toWei(BOB_DEPOSIT_ETH, 'ether'))


def bob_to_charlie(
        prover_client: ProverClient,
        mixer_instance: Any,
        mk_root: str,
        input1: Tuple[int, util_pb2.ZethNote],
        bob_eth_address: str,
        keystore: mock.KeyStore,
        mk_tree_depth: int,
        zksnark: IZKSnarkProvider) -> contracts.MixResult:
    print(
        f"=== Bob transfers {BOB_TO_CHARLIE_ETH}ETH to Charlie from his funds " +
        "on the mixer ===")

    bob_ask = keystore["Bob"].addr_sk.a_sk
    charlie_addr = keystore["Charlie"].addr_pk
    bob_addr = keystore["Bob"].addr_pk

    # Coin for Bob (change)
    value_to_bob = to_zeth_units(str(BOB_TO_CHARLIE_ETH), 'ether')
    output0 = (bob_addr, value_to_bob)
    # Coin for Charlie
    value_to_charlie = to_zeth_units(str(BOB_TO_CHARLIE_CHANGE_ETH), 'ether')
    output1 = (charlie_addr, value_to_charlie)

    # Send the tx
    mk_tree = contracts.get_merkle_tree(mixer_instance)
    return joinsplit.zeth_spend(
        prover_client,
        mixer_instance,
        mk_root,
        mk_tree,
        mk_tree_depth,
        zksnark,
        joinsplit.OwnershipKeyPair(bob_ask, bob_addr.a_pk),
        bob_eth_address,
        [input1],
        [output0, output1],
        ZERO_UNITS_HEX,
        ZERO_UNITS_HEX,
        W3.toWei(1, 'wei'))


def charlie_withdraw(
        prover_client: ProverClient,
        mixer_instance: Any,
        mk_root: str,
        input1: Tuple[int, util_pb2.ZethNote],
        charlie_eth_address: str,
        keystore: mock.KeyStore,
        mk_tree_depth: int,
        zksnark: IZKSnarkProvider) -> contracts.MixResult:
    print(
        f" === Charlie withdraws {CHARLIE_WITHDRAW_ETH}ETH from his funds " +
        "on the Mixer ===")

    mk_tree = contracts.get_merkle_tree(mixer_instance)
    charlie_pk = keystore["Charlie"].addr_pk
    charlie_apk = charlie_pk.a_pk
    charlie_ask = keystore["Charlie"].addr_sk.a_sk
    charlie_ownership_key = \
        joinsplit.OwnershipKeyPair(charlie_ask, charlie_apk)

    return joinsplit.zeth_spend(
        prover_client,
        mixer_instance,
        mk_root,
        mk_tree,
        mk_tree_depth,
        zksnark,
        charlie_ownership_key,
        charlie_eth_address,
        [input1],
        [(charlie_pk, to_zeth_units(str(CHARLIE_WITHDRAW_CHANGE_ETH), 'ether'))],
        ZERO_UNITS_HEX,
        int64_to_hex(to_zeth_units(str(CHARLIE_WITHDRAW_ETH), 'ether')),
        W3.toWei(1, 'wei'))


def charlie_double_withdraw(
        prover_client: ProverClient,
        mixer_instance: Any,
        mk_root: str,
        input1: Tuple[int, util_pb2.ZethNote],
        charlie_eth_address: str,
        keystore: mock.KeyStore,
        mk_tree_depth: int,
        zksnark: IZKSnarkProvider) -> contracts.MixResult:
    """
    Charlie tries to carry out a double spending by modifying the value of the
    nullifier of the previous payment
    """
    print(
        f" === Charlie attempts to withdraw {CHARLIE_WITHDRAW_ETH}ETH once " +
        "more (double spend) one of his note on the Mixer ===")

    charlie_apk = keystore["Charlie"].addr_pk.a_pk
    charlie_ask = keystore["Charlie"].addr_sk.a_sk

    mk_byte_tree = contracts.get_merkle_tree(mixer_instance)
    mk_path1 = compute_merkle_path(input1[0], mk_tree_depth, mk_byte_tree)

    # Create the an additional dummy input for the JoinSplit
    input2 = joinsplit.get_dummy_input_and_address(charlie_apk)
    dummy_mk_path = mock.get_dummy_merkle_path(mk_tree_depth)

    note1_value = to_zeth_units(str(CHARLIE_WITHDRAW_CHANGE_ETH), 'ether')
    v_out = to_zeth_units(str(CHARLIE_WITHDRAW_ETH), 'ether')

    (output_note1, output_note2, proof_json, signing_keypair) = \
        joinsplit.get_proof_joinsplit_2_by_2(
            prover_client,
            mk_root,
            input1,
            mk_path1,
            input2,
            dummy_mk_path,
            charlie_ask,  # sender
            (charlie_apk, note1_value),  # recipient1
            (charlie_apk, 0),  # recipient2
            ZERO_UNITS_HEX,  # v_in
            int64_to_hex(v_out),  # v_out
            zksnark
        )

    # ### ATTACK BLOCK
    # Add malicious nullifiers (located at index 2 and 4 in the array of inputs)
    # See: https://github.com/clearmatics/zeth/issues/38
    r = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # noqa
    print("proof_json => ", proof_json)
    print("proof_json[inputs][2] => ", proof_json["inputs"][2])
    print("proof_json[inputs][4] => ", proof_json["inputs"][4])
    proof_json["inputs"][2] = hex(int(proof_json["inputs"][2], 16) + r)
    proof_json["inputs"][4] = hex(int(proof_json["inputs"][4], 16) + r)
    # ### ATTACK BLOCK

    # construct pk object from bytes
    pk_charlie = keystore["Charlie"].addr_pk.k_pk

    # encrypt the coins
    (sender_eph_pk, ciphertexts) = joinsplit.encrypt_notes([
        (output_note1, pk_charlie),
        (output_note2, pk_charlie)])

    # Compute the joinSplit signature
    joinsplit_sig = joinsplit.sign_mix_tx(
        sender_eph_pk, ciphertexts, proof_json, signing_keypair)

    return contracts.mix(
        mixer_instance,
        sender_eph_pk,
        ciphertexts[0],
        ciphertexts[1],
        proof_json,
        signing_keypair.pk,
        joinsplit_sig,
        charlie_eth_address,
        # Pay an arbitrary amount (1 wei here) that will be refunded since the
        # `mix` function is payable
        W3.toWei(1, 'wei'),
        4000000,
        zksnark
    )
