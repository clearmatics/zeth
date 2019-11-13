import zeth.joinsplit as joinsplit
import zeth.contracts as contracts
from zeth.prover_client import ProverClient
from zeth.zksnark import IZKSnarkProvider
from zeth.utils import to_zeth_units, int64_to_hex, encode_to_hash
import test_commands.mock as mock
import api.util_pb2 as util_pb2

from hashlib import sha256
from web3 import Web3, HTTPProvider  # type: ignore
from typing import List, Any

W3 = Web3(HTTPProvider("http://localhost:8545"))

ZERO_UNITS_HEX = "0000000000000000"
BOB_DEPOSIT_ETH = 200
BOB_SPLIT_1_ETH = 100
BOB_SPLIT_2_ETH = 100

BOB_TO_CHARLIE_ETH = 50
BOB_TO_CHARLIE_CHANGE_ETH = BOB_SPLIT_1_ETH - BOB_TO_CHARLIE_ETH

CHARLIE_WITHDRAW_ETH = 10.5
CHARLIE_WITHDRAW_CHANGE_ETH = 39.5


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
    bob_apk = keystore["Bob"].addr_pk.a_pk
    bob_ask = keystore["Bob"].addr_sk.a_sk
    # Create the JoinSplit dummy inputs for the deposit
    (input_note1, _input_nullifier1, input_address1) = mock.get_dummy_input(
        bob_apk, bob_ask)
    (input_note2, _input_nullifier2, input_address2) = mock.get_dummy_input(
        bob_apk, bob_ask)
    dummy_mk_path = mock.get_dummy_merkle_path(mk_tree_depth)

    note1_value = to_zeth_units(str(BOB_SPLIT_1_ETH), 'ether')
    note2_value = to_zeth_units(str(BOB_SPLIT_2_ETH), 'ether')
    v_in = to_zeth_units(str(BOB_DEPOSIT_ETH), 'ether')

    (output_note1, output_note2, proof_json, signing_keypair) = \
        joinsplit.get_proof_joinsplit_2_by_2(
            prover_client,
            mk_root,
            input_note1,
            input_address1,
            dummy_mk_path,
            input_note2,
            input_address2,
            dummy_mk_path,
            bob_ask,  # sender
            bob_apk,  # recipient1
            bob_apk,  # recipient2
            int64_to_hex(note1_value),  # value output note 1
            int64_to_hex(note2_value),  # value output note 2
            int64_to_hex(v_in),  # v_in
            ZERO_UNITS_HEX,  # v_out
            zksnark
    )

    # construct pk object from bytes
    pk_bob = keystore["Bob"].addr_pk.k_pk

    # encrypt the coins
    (pk_sender, ciphertexts) = joinsplit.encrypt_notes([
        (output_note1, pk_bob),
        (output_note2, pk_bob)])

    # Hash the pk_sender and cipher-texts
    ciphers = pk_sender + ciphertexts[0] + ciphertexts[1]
    hash_ciphers = sha256(ciphers).hexdigest()

    # Hash the proof
    proof: List[str] = []
    for key in proof_json.keys():
        if key != "inputs":
            proof.extend(proof_json[key])
    hash_proof = sha256(encode_to_hash(proof)).hexdigest()

    # Encode and hash the primary inputs
    encoded_inputs = joinsplit.encode_pub_input_to_hash(proof_json["inputs"])
    hash_inputs = sha256(encoded_inputs).hexdigest()

    # Compute the joinSplit signature
    joinsplit_sig = joinsplit.sign(
        signing_keypair, hash_ciphers, hash_proof, hash_inputs)

    return contracts.mix(
        mixer_instance,
        pk_sender,
        ciphertexts[0],
        ciphertexts[1],
        proof_json,
        signing_keypair.pk,
        joinsplit_sig,
        bob_eth_address,
        W3.toWei(BOB_DEPOSIT_ETH, 'ether'),
        4000000,
        zksnark
    )


def bob_to_charlie(
        prover_client: ProverClient,
        mixer_instance: Any,
        mk_root: str,
        mk_path1: List[str],
        input_note1: util_pb2.ZethNote,
        input_address1: int,
        bob_eth_address: str,
        keystore: mock.KeyStore,
        mk_tree_depth: int,
        zksnark: IZKSnarkProvider) -> contracts.MixResult:
    print(
        f"=== Bob transfers {BOB_TO_CHARLIE_ETH}ETH to Charlie from his funds " +
        "on the mixer ===")

    # We generate a coin for Charlie (recipient1)
    charlie_apk = keystore["Charlie"].addr_pk.a_pk
    # We generate a coin for Bob: the change (recipient2)
    bob_apk = keystore["Bob"].addr_pk.a_pk
    # Bob is the sender
    bob_ask = keystore["Bob"].addr_sk.a_sk

    # Create the an additional dummy input for the JoinSplit
    (input_note2, _input_nullifier2, input_address2) = mock.get_dummy_input(
        bob_apk, bob_ask)
    dummy_mk_path = mock.get_dummy_merkle_path(mk_tree_depth)

    note1_value = to_zeth_units(str(BOB_TO_CHARLIE_ETH), 'ether')
    note2_value = to_zeth_units(str(BOB_TO_CHARLIE_CHANGE_ETH), 'ether')

    (output_note1, output_note2, proof_json, signing_keypair) = \
        joinsplit.get_proof_joinsplit_2_by_2(
            prover_client,
            mk_root,
            input_note1,
            input_address1,
            mk_path1,
            input_note2,
            input_address2,
            dummy_mk_path,
            bob_ask,  # sender
            bob_apk,  # recipient1 (change)
            charlie_apk,  # recipient2 (transfer)
            int64_to_hex(note1_value),  # value output note 1
            int64_to_hex(note2_value),  # value output note 2
            ZERO_UNITS_HEX,  # v_in
            ZERO_UNITS_HEX,  # v_out
            zksnark
        )

    # Encrypt the output notes for the senders
    (pk_sender, ciphertexts) = joinsplit.encrypt_notes([
        (output_note1, keystore["Bob"].addr_pk.k_pk),
        (output_note2, keystore["Charlie"].addr_pk.k_pk)])

    # Hash the pk_sender and cipher-texts
    ciphers = pk_sender + ciphertexts[0] + ciphertexts[1]
    hash_ciphers = sha256(ciphers).hexdigest()

    # Hash the proof
    proof: List[int] = []
    for key in proof_json.keys():
        if key != "inputs":
            proof.extend(proof_json[key])
    hash_proof = sha256(encode_to_hash(proof)).hexdigest()

    # Encode and hash the primary inputs
    encoded_inputs = joinsplit.encode_pub_input_to_hash(proof_json["inputs"])
    hash_inputs = sha256(encoded_inputs).hexdigest()

    # Compute the joinSplit signature
    joinsplit_sig = joinsplit.sign(
        signing_keypair, hash_ciphers, hash_proof, hash_inputs)

    return contracts.mix(
        mixer_instance,
        pk_sender,
        ciphertexts[0],
        ciphertexts[1],
        proof_json,
        signing_keypair.pk,
        joinsplit_sig,
        bob_eth_address,
        # Pay an arbitrary amount (1 wei here) that will be refunded since the
        # `mix` function is payable
        W3.toWei(1, 'wei'),
        4000000,
        zksnark
    )


def charlie_withdraw(
        prover_client: ProverClient,
        mixer_instance: Any,
        mk_root: str,
        mk_path1: List[str],
        input_note1: util_pb2.ZethNote,
        input_address1: int,
        charlie_eth_address: str,
        keystore: mock.KeyStore,
        mk_tree_depth: int,
        zksnark: IZKSnarkProvider) -> contracts.MixResult:
    print(
        f" === Charlie withdraws {CHARLIE_WITHDRAW_ETH}ETH from his funds " +
        "on the Mixer ===")

    charlie_apk = keystore["Charlie"].addr_pk.a_pk
    charlie_ask = keystore["Charlie"].addr_sk.a_sk

    # Create the an additional dummy input for the JoinSplit
    (input_note2, _input_nullifier2, input_address2) = mock.get_dummy_input(
        charlie_apk, charlie_ask)
    dummy_mk_path = mock.get_dummy_merkle_path(mk_tree_depth)

    note1_value = to_zeth_units(str(CHARLIE_WITHDRAW_CHANGE_ETH), 'ether')
    v_out = to_zeth_units(str(CHARLIE_WITHDRAW_ETH), 'ether')

    (output_note1, output_note2, proof_json, signing_keypair) = \
        joinsplit.get_proof_joinsplit_2_by_2(
            prover_client,
            mk_root,
            input_note1,
            input_address1,
            mk_path1,
            input_note2,
            input_address2,
            dummy_mk_path,
            charlie_ask,  # sender
            charlie_apk,  # recipient1
            charlie_apk,  # recipient2
            int64_to_hex(note1_value),  # value output note 1
            ZERO_UNITS_HEX,  # value output note 2
            ZERO_UNITS_HEX,  # v_in
            int64_to_hex(v_out),  # v_out
            zksnark
        )

    # construct pk object from bytes
    pk_charlie = keystore["Charlie"].addr_pk.k_pk

    # encrypt the coins
    (pk_sender, ciphertexts) = joinsplit.encrypt_notes([
        (output_note1, pk_charlie),
        (output_note2, pk_charlie)])

    # Hash the pk_sender and cipher-texts
    ciphers = pk_sender + ciphertexts[0] + ciphertexts[1]
    hash_ciphers = sha256(ciphers).hexdigest()

    # Hash the proof
    proof: List[str] = []
    for key in proof_json.keys():
        if key != "inputs":
            proof.extend(proof_json[key])
    hash_proof = sha256(encode_to_hash(proof)).hexdigest()

    # Encode and hash the primary inputs
    encoded_inputs = joinsplit.encode_pub_input_to_hash(proof_json["inputs"])
    hash_inputs = sha256(encoded_inputs).hexdigest()

    # Compute the joinSplit signature
    joinsplit_sig = joinsplit.sign(
        signing_keypair, hash_ciphers, hash_proof, hash_inputs)

    return contracts.mix(
        mixer_instance,
        pk_sender,
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


def charlie_double_withdraw(
        prover_client: ProverClient,
        mixer_instance: Any,
        mk_root: str,
        mk_path1: List[str],
        input_note1: util_pb2.ZethNote,
        input_address1: int,
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

    # Create the an additional dummy input for the JoinSplit
    (input_note2, _input_nullifier2, input_address2) = \
        mock.get_dummy_input(charlie_apk, charlie_ask)
    dummy_mk_path = mock.get_dummy_merkle_path(mk_tree_depth)

    note1_value = to_zeth_units(str(CHARLIE_WITHDRAW_CHANGE_ETH), 'ether')
    v_out = to_zeth_units(str(CHARLIE_WITHDRAW_ETH), 'ether')

    (output_note1, output_note2, proof_json, signing_keypair) = \
        joinsplit.get_proof_joinsplit_2_by_2(
            prover_client,
            mk_root,
            input_note1,
            input_address1,
            mk_path1,
            input_note2,
            input_address2,
            dummy_mk_path,
            charlie_ask,  # sender
            charlie_apk,  # recipient1
            charlie_apk,  # recipient2
            int64_to_hex(note1_value),  # value output note 1
            ZERO_UNITS_HEX,  # value output note 2
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
    (pk_sender, ciphertexts) = joinsplit.encrypt_notes([
        (output_note1, pk_charlie),
        (output_note2, pk_charlie)])

    # Hash the pk_sender and cipher-texts
    ciphers = pk_sender + ciphertexts[0] + ciphertexts[1]
    hash_ciphers = sha256(ciphers).hexdigest()

    # Hash the proof
    proof: List[str] = []
    for key in proof_json.keys():
        if key != "inputs":
            proof.extend(proof_json[key])
    hash_proof = sha256(encode_to_hash(proof)).hexdigest()

    # Encode and hash the primary inputs
    encoded_inputs = joinsplit.encode_pub_input_to_hash(proof_json["inputs"])
    hash_inputs = sha256(encoded_inputs).hexdigest()

    # Compute the joinSplit signature
    joinsplit_sig = joinsplit.sign(
        signing_keypair, hash_ciphers, hash_proof, hash_inputs)

    return contracts.mix(
        mixer_instance,
        pk_sender,
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
