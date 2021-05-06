#!/usr/bin/env python3

# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.zeth_address import ZethAddressPub
from zeth.core.mixer_client import MixCallDescription, MixParameters, MixResult, \
    MixerClient, OwnershipKeyPair, JoinsplitSigVerificationKey, ComputeHSigCB, \
    JoinsplitSigKeyPair, parse_mix_call, joinsplit_sign, encrypt_notes, \
    get_dummy_input_and_address, compute_h_sig
from zeth.core.prover_client import ProverClient
from zeth.core.zksnark import IZKSnarkProvider, ExtendedProof
import zeth.core.signing as signing
from zeth.core.merkle_tree import MerkleTree
from zeth.core.utils import EtherValue
from zeth.api.zeth_messages_pb2 import ZethNote
import test_commands.mock as mock

from os import urandom
from web3 import Web3  # type: ignore
from typing import List, Tuple, Optional

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
        print("Node: " + Web3.toHex(node)[2:])


def wait_for_tx_update_mk_tree(
        zeth_client: MixerClient,
        mk_tree: MerkleTree,
        tx_hash: str) -> MixResult:
    tx_receipt = zeth_client.web3.eth.waitForTransactionReceipt(tx_hash, 10000)
    result = parse_mix_call(zeth_client.mixer_instance, tx_receipt)
    for out_ev in result.output_events:
        mk_tree.insert(out_ev.commitment)

    if mk_tree.recompute_root() != result.new_merkle_root:
        raise Exception("Merkle root mismatch between log and local tree")
    return result


def get_mix_parameters_components(
        zeth_client: MixerClient,
        prover_client: ProverClient,
        mk_tree: MerkleTree,
        sender_ownership_keypair: OwnershipKeyPair,
        inputs: List[Tuple[int, ZethNote]],
        outputs: List[Tuple[ZethAddressPub, EtherValue]],
        v_in: EtherValue,
        v_out: EtherValue,
        compute_h_sig_cb: Optional[ComputeHSigCB] = None
) -> Tuple[ZethNote, ZethNote, ExtendedProof, List[int], JoinsplitSigKeyPair]:
    """
    Manually create the components required for MixParameters. The tests below
    manipulate these to create custom MixParameters as part of attacks.
    """
    mix_call_desc = MixCallDescription(
        mk_tree,
        sender_ownership_keypair,
        inputs,
        outputs,
        v_in,
        v_out,
        compute_h_sig_cb)
    prover_inputs, signing_keypair = zeth_client.create_prover_inputs(
        mix_call_desc)
    ext_proof, public_data = prover_client.get_proof(prover_inputs)
    return (
        prover_inputs.js_outputs[0],
        prover_inputs.js_outputs[1],
        ext_proof,
        public_data,
        signing_keypair)


def bob_deposit(
        zeth_client: MixerClient,
        prover_client: ProverClient,
        mk_tree: MerkleTree,
        bob_eth_address: str,
        keystore: mock.KeyStore,
        tx_value: Optional[EtherValue] = None) -> MixResult:
    print(
        f"=== Bob deposits {BOB_DEPOSIT_ETH} ETH for himself and splits into " +
        f"note1: {BOB_SPLIT_1_ETH}ETH, note2: {BOB_SPLIT_2_ETH}ETH ===")

    bob_js_keypair = keystore["Bob"]
    bob_addr = keystore["Bob"].addr_pk

    outputs = [
        (bob_addr, EtherValue(BOB_SPLIT_1_ETH)),
        (bob_addr, EtherValue(BOB_SPLIT_2_ETH)),
    ]

    tx_hash = zeth_client.deposit(
        prover_client,
        mk_tree,
        bob_js_keypair,
        bob_eth_address,
        None,
        EtherValue(BOB_DEPOSIT_ETH),
        outputs,
        tx_value)
    return wait_for_tx_update_mk_tree(zeth_client, mk_tree, tx_hash)


def bob_to_charlie(
        zeth_client: MixerClient,
        prover_client: ProverClient,
        mk_tree: MerkleTree,
        input1: Tuple[int, ZethNote],
        bob_eth_address: str,
        keystore: mock.KeyStore) -> MixResult:
    print(
        f"=== Bob transfers {BOB_TO_CHARLIE_ETH}ETH to Charlie from his funds " +
        "on the mixer ===")

    bob_ask = keystore["Bob"].addr_sk.a_sk
    charlie_addr = keystore["Charlie"].addr_pk
    bob_addr = keystore["Bob"].addr_pk

    # Coin for Bob (change)
    output0 = (bob_addr, EtherValue(BOB_TO_CHARLIE_ETH))
    # Coin for Charlie
    output1 = (charlie_addr, EtherValue(BOB_TO_CHARLIE_CHANGE_ETH))

    # Send the tx
    tx_hash = zeth_client.joinsplit(
        prover_client,
        mk_tree,
        OwnershipKeyPair(bob_ask, bob_addr.a_pk),
        bob_eth_address,
        None,
        [input1],
        [output0, output1],
        EtherValue(0),
        EtherValue(0),
        EtherValue(1, 'wei'))
    return wait_for_tx_update_mk_tree(zeth_client, mk_tree, tx_hash)


def charlie_withdraw(
        zeth_client: MixerClient,
        prover_client: ProverClient,
        mk_tree: MerkleTree,
        input1: Tuple[int, ZethNote],
        charlie_eth_address: str,
        keystore: mock.KeyStore) -> MixResult:
    print(
        f" === Charlie withdraws {CHARLIE_WITHDRAW_ETH}ETH from his funds " +
        "on the Mixer ===")

    charlie_pk = keystore["Charlie"].addr_pk
    charlie_apk = charlie_pk.a_pk
    charlie_ask = keystore["Charlie"].addr_sk.a_sk
    charlie_ownership_key = \
        OwnershipKeyPair(charlie_ask, charlie_apk)

    tx_hash = zeth_client.joinsplit(
        prover_client,
        mk_tree,
        charlie_ownership_key,
        charlie_eth_address,
        None,
        [input1],
        [(charlie_pk, EtherValue(CHARLIE_WITHDRAW_CHANGE_ETH))],
        EtherValue(0),
        EtherValue(CHARLIE_WITHDRAW_ETH),
        EtherValue(1, 'wei'))
    return wait_for_tx_update_mk_tree(zeth_client, mk_tree, tx_hash)


def charlie_double_withdraw(
        zeth_client: MixerClient,
        prover_client: ProverClient,
        zksnark: IZKSnarkProvider,
        mk_tree: MerkleTree,
        input1: Tuple[int, ZethNote],
        charlie_eth_address: str,
        keystore: mock.KeyStore) -> MixResult:
    """
    Charlie tries to carry out a double spending by modifying the value of the
    nullifier of the previous payment
    """
    pp = zeth_client.prover_config.pairing_parameters
    scalar_field_mod = pp.scalar_field_mod()
    scalar_field_capacity = pp.scalar_field_capacity

    print(
        f" === Charlie attempts to withdraw {CHARLIE_WITHDRAW_ETH}ETH once " +
        "more (double spend) one of his note on the Mixer ===")

    charlie_addr = keystore["Charlie"]
    charlie_apk = charlie_addr.addr_pk.a_pk

    # Create the an additional dummy input for the MixerClient
    input2 = get_dummy_input_and_address(charlie_apk)

    note1_value = EtherValue(CHARLIE_WITHDRAW_CHANGE_ETH)
    v_out = EtherValue(CHARLIE_WITHDRAW_ETH)

    # ### ATTACK BLOCK
    # Add malicious nullifiers: we reuse old nullifiers to double spend by
    # adding $r$ to them so that they have the same value as before in Z_r,
    # and so the zksnark verification passes, but have different values in
    # {0;1}^256 so that they appear different to the contract.
    # See: https://github.com/clearmatics/zeth/issues/38

    attack_primary_input3: int = 0
    attack_primary_input4: int = 0

    def compute_h_sig_attack_nf(
            nf0: bytes,
            nf1: bytes,
            sign_vk: JoinsplitSigVerificationKey) -> bytes:
        # We disassemble the nfs to get the formatting of the primary inputs
        input_nullifier0 = nf0.hex()
        input_nullifier1 = nf1.hex()
        nf0_rev = "{0:0256b}".format(int(input_nullifier0, 16))
        primary_input3_bits = nf0_rev[:scalar_field_capacity]
        primary_input3_res_bits = nf0_rev[scalar_field_capacity:]
        nf1_rev = "{0:0256b}".format(int(input_nullifier1, 16))
        primary_input4_bits = nf1_rev[:scalar_field_capacity]
        primary_input4_res_bits = nf1_rev[scalar_field_capacity:]

        # We perform the attack, recoding the modified public input values
        nonlocal attack_primary_input3
        nonlocal attack_primary_input4
        attack_primary_input3 = int(primary_input3_bits, 2) + scalar_field_mod
        attack_primary_input4 = int(primary_input4_bits, 2) + scalar_field_mod

        # We reassemble the nfs
        attack_primary_input3_bits = "{0:0256b}".format(attack_primary_input3)
        attack_nf0_bits = attack_primary_input3_bits[
            len(attack_primary_input3_bits) - scalar_field_capacity:] +\
            primary_input3_res_bits
        attack_nf0 = "{0:064x}".format(int(attack_nf0_bits, 2))
        attack_primary_input4_bits = "{0:0256b}".format(attack_primary_input4)
        attack_nf1_bits = attack_primary_input4_bits[
            len(attack_primary_input4_bits) - scalar_field_capacity:] +\
            primary_input4_res_bits
        attack_nf1 = "{0:064x}".format(int(attack_nf1_bits, 2))
        return compute_h_sig(
            bytes.fromhex(attack_nf0), bytes.fromhex(attack_nf1), sign_vk)

    output_note1, output_note2, proof, public_data, signing_keypair = \
        get_mix_parameters_components(
            zeth_client,
            prover_client,
            mk_tree,
            keystore["Charlie"].ownership_keypair(),  # sender
            [input1, input2],
            [(charlie_addr.addr_pk, note1_value),
             (charlie_addr.addr_pk, EtherValue(0))],
            EtherValue(0),
            v_out,
            compute_h_sig_attack_nf)

    # Update the primary inputs to the modified nullifiers, since libsnark
    # overwrites them with values in Z_p

    assert attack_primary_input3 != 0
    assert attack_primary_input4 != 0

    print("proof = ", proof)
    print("public_data[3] = ", public_data[3])
    print("public_data[4] = ", public_data[4])
    public_data[3] = attack_primary_input3
    public_data[4] = attack_primary_input4
    # ### ATTACK BLOCK

    # construct pk object from bytes
    pk_charlie = keystore["Charlie"].addr_pk.k_pk

    # encrypt the coins
    ciphertexts = encrypt_notes([
        (output_note1, pk_charlie),
        (output_note2, pk_charlie)])

    # Compute the joinSplit signature
    joinsplit_sig_charlie = joinsplit_sign(
        zksnark,
        pp,
        signing_keypair,
        charlie_eth_address,
        ciphertexts,
        proof,
        public_data)

    mix_params = MixParameters(
        proof,
        public_data,
        signing_keypair.vk,
        joinsplit_sig_charlie,
        ciphertexts)

    tx_hash = zeth_client.mix(
        mix_params,
        charlie_eth_address,
        # Pay an arbitrary amount (1 wei here) that will be refunded since the
        # `mix` function is payable
        None,
        EtherValue(1, 'wei'))
    return wait_for_tx_update_mk_tree(zeth_client, mk_tree, tx_hash)


def charlie_corrupt_bob_deposit(
        zeth_client: MixerClient,
        prover_client: ProverClient,
        zksnark: IZKSnarkProvider,
        mk_tree: MerkleTree,
        bob_eth_address: str,
        charlie_eth_address: str,
        keystore: mock.KeyStore) -> MixResult:
    """
    Charlie tries to break transaction malleability and corrupt the coins
    bob is sending in a transaction
    She does so by intercepting bob's transaction and either:
    - case 1: replacing the ciphertexts (or sender_eph_pk) by garbage/arbitrary
      data
    - case 2: replacing the ciphertexts by garbage/arbitrary data and using a
      new OT-signature
    - case 3: Charlie replays the mix call of Bob, to try to receive the vout
    Both attacks should fail,
    - case 1: the signature check should fail, else Charlie broke UF-CMA of the
      OT signature
    - case 2: the h_sig/vk verification should fail, as h_sig is not a function
      of vk any longer
    - case 3: the signature check should fail, because `msg.sender` will no match
      the value used in the mix parameters (Bob's Ethereum Address).
    NB. If the adversary were to corrupt the ciphertexts (or the encryption key),
    replace the OT-signature by a new one and modify the h_sig accordingly so that
    the check on the signature verification (key h_sig/vk) passes, the proof would
    not verify, which is why we do not test this case.
    """
    print(
        f"=== Bob deposits {BOB_DEPOSIT_ETH} ETH for himself and split into " +
        f"note1: {BOB_SPLIT_1_ETH}ETH, note2: {BOB_SPLIT_2_ETH}ETH " +
        "but Charlie attempts to corrupt the transaction ===")
    bob_addr_pk = keystore["Bob"]
    bob_apk = bob_addr_pk.addr_pk.a_pk

    # Get pairing parameters
    pp = prover_client.get_configuration().pairing_parameters

    # Create the JoinSplit dummy inputs for the deposit
    input1 = get_dummy_input_and_address(bob_apk)
    input2 = get_dummy_input_and_address(bob_apk)

    note1_value = EtherValue(BOB_SPLIT_1_ETH)
    note2_value = EtherValue(BOB_SPLIT_2_ETH)

    v_in = EtherValue(BOB_DEPOSIT_ETH)

    output_note1, output_note2, proof, public_data, joinsplit_keypair = \
        get_mix_parameters_components(
            zeth_client,
            prover_client,
            mk_tree,
            keystore["Bob"].ownership_keypair(),
            [input1, input2],
            [(bob_addr_pk.addr_pk, note1_value),
             (bob_addr_pk.addr_pk, note2_value)],
            v_in,
            EtherValue(0))  # v_out

    # Encrypt the coins to bob
    pk_bob = keystore["Bob"].addr_pk.k_pk
    ciphertexts = encrypt_notes([
        (output_note1, pk_bob),
        (output_note2, pk_bob)])

    # ### ATTACK BLOCK
    # Charlie intercepts Bob's deposit, corrupts it and
    # sends her transaction before Bob's transaction is accepted

    # Case 1: replacing the ciphertexts by garbage/arbitrary data
    # Corrupt the ciphertexts
    # (another way would have been to overwrite sender_eph_pk)
    fake_ciphertext0 = urandom(32)
    fake_ciphertext1 = urandom(32)

    result_corrupt1 = None
    try:
        joinsplit_sig_charlie = joinsplit_sign(
            zksnark,
            pp,
            joinsplit_keypair,
            charlie_eth_address,
            ciphertexts,
            proof,
            public_data)

        mix_params = MixParameters(
            proof,
            public_data,
            joinsplit_keypair.vk,
            joinsplit_sig_charlie,
            [fake_ciphertext0, fake_ciphertext1])
        tx_hash = zeth_client.mix(
            mix_params,
            charlie_eth_address,
            None,
            EtherValue(BOB_DEPOSIT_ETH))
        result_corrupt1 = \
            wait_for_tx_update_mk_tree(zeth_client, mk_tree, tx_hash)
    except Exception as e:
        print(
            "Charlie's first corruption attempt" +
            f" successfully rejected! (msg: {e})"
        )
    assert(result_corrupt1 is None), \
        "Charlie managed to corrupt Bob's deposit the first time!"
    print("")

    # Case 2: replacing the ciphertexts by garbage/arbitrary data and
    # using a new OT-signature
    # Corrupt the ciphertexts
    fake_ciphertext0 = urandom(32)
    fake_ciphertext1 = urandom(32)
    new_joinsplit_keypair = signing.gen_signing_keypair()

    # Sign the primary inputs, sender_eph_pk and the ciphertexts

    result_corrupt2 = None
    try:
        joinsplit_sig_charlie = joinsplit_sign(
            zksnark,
            pp,
            new_joinsplit_keypair,
            charlie_eth_address,
            [fake_ciphertext0, fake_ciphertext1],
            proof,
            public_data)
        mix_params = MixParameters(
            proof,
            public_data,
            new_joinsplit_keypair.vk,
            joinsplit_sig_charlie,
            [fake_ciphertext0, fake_ciphertext1])
        tx_hash = zeth_client.mix(
            mix_params,
            charlie_eth_address,
            None,
            EtherValue(BOB_DEPOSIT_ETH))
        result_corrupt2 = \
            wait_for_tx_update_mk_tree(zeth_client, mk_tree, tx_hash)
    except Exception as e:
        print(
            "Charlie's second corruption attempt" +
            f" successfully rejected! (msg: {e})"
        )
    assert(result_corrupt2 is None), \
        "Charlie managed to corrupt Bob's deposit the second time!"

    # Case3: Charlie uses the correct mix data, but attempts to send the mix
    # call from his own address (thereby receiving the output).
    result_corrupt3 = None
    try:
        joinsplit_sig_bob = joinsplit_sign(
            zksnark,
            pp,
            joinsplit_keypair,
            bob_eth_address,
            ciphertexts,
            proof,
            public_data)
        mix_params = MixParameters(
            proof,
            public_data,
            joinsplit_keypair.vk,
            joinsplit_sig_bob,
            ciphertexts)
        tx_hash = zeth_client.mix(
            mix_params,
            charlie_eth_address,
            None,
            EtherValue(BOB_DEPOSIT_ETH),
            4000000)
        result_corrupt3 = \
            wait_for_tx_update_mk_tree(zeth_client, mk_tree, tx_hash)
    except Exception as e:
        print(
            "Charlie's third corruption attempt" +
            f" successfully rejected! (msg: {e})"
        )
    assert(result_corrupt3 is None), \
        "Charlie managed to corrupt Bob's deposit the third time!"
    # ### ATTACK BLOCK

    # Bob transaction is finally mined
    joinsplit_sig_bob = joinsplit_sign(
        zksnark,
        pp,
        joinsplit_keypair,
        bob_eth_address,
        ciphertexts,
        proof,
        public_data)
    mix_params = MixParameters(
        proof,
        public_data,
        joinsplit_keypair.vk,
        joinsplit_sig_bob,
        ciphertexts)
    tx_hash = zeth_client.mix(
        mix_params,
        bob_eth_address,
        None,
        EtherValue(BOB_DEPOSIT_ETH))
    return wait_for_tx_update_mk_tree(zeth_client, mk_tree, tx_hash)
