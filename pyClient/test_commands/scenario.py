import zeth.utils
import zeth.grpc
import zeth.contracts
import test_commands.mock as mock

import json
from hashlib import sha256
import nacl.utils  # type: ignore
from nacl.public import PrivateKey  # type: ignore
from web3 import Web3, HTTPProvider  # type: ignore

w3 = Web3(HTTPProvider("http://localhost:8545"))

zero_units_hex = "0000000000000000"
BOB_DEPOSIT_ETH = 200
BOB_SPLIT_1_ETH = 100
BOB_SPLIT_2_ETH = 100

BOB_TO_CHARLIE_ETH = 50
BOB_TO_CHARLIE_CHANGE_ETH = BOB_SPLIT_1_ETH - BOB_TO_CHARLIE_ETH

CHARLIE_WITHDRAW_ETH = 10.5
CHARLIE_WITHDRAW_CHANGE_ETH = 39.5


def bob_deposit(
        test_grpc_endpoint,
        mixer_instance,
        mk_root,
        bob_eth_address,
        keystore,
        mk_tree_depth,
        zksnark):
    print(
        f"=== Bob deposits {BOB_DEPOSIT_ETH} ETH for himself and splits into " +
        f"note1: {BOB_SPLIT_1_ETH}ETH, note2: {BOB_SPLIT_2_ETH}ETH ===")
    bob_apk = keystore["Bob"]["addr_pk"]["apk"]
    bob_ask = keystore["Bob"]["addr_sk"]["ask"]
    # Create the JoinSplit dummy inputs for the deposit
    (input_note1, input_nullifier1, input_address1) = mock.get_dummy_input(bob_apk, bob_ask)
    (input_note2, input_nullifier2, input_address2) = mock.get_dummy_input(bob_apk, bob_ask)
    dummy_mk_path = mock.get_dummy_merkle_path(mk_tree_depth)

    note1_value = zeth.utils.to_zeth_units(str(BOB_SPLIT_1_ETH), 'ether')
    note2_value = zeth.utils.to_zeth_units(str(BOB_SPLIT_2_ETH), 'ether')
    v_in = zeth.utils.to_zeth_units(str(BOB_DEPOSIT_ETH), 'ether')

    (output_note1, output_note2, proof_json, joinsplit_keypair) = \
        zeth.grpc.get_proof_joinsplit_2_by_2(
            test_grpc_endpoint,
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
            zeth.utils.int64_to_hex(note1_value),  # value output note 1
            zeth.utils.int64_to_hex(note2_value),  # value output note 2
            zeth.utils.int64_to_hex(v_in),  # v_in
            zero_units_hex,  # v_out
            zksnark
    )

    output_note1_str = json.dumps(zeth.grpc.parse_zeth_note(output_note1))
    output_note2_str = json.dumps(zeth.grpc.parse_zeth_note(output_note2))

    # generate ephemeral ec25519 key
    eph_sk_bob = PrivateKey.generate()

    # construct pk object from bytes
    pk_bob = zeth.utils.get_public_key_from_bytes(keystore["Bob"]["addr_pk"]["enc_pk"])

    # encrypt the coins
    ciphertext1 = zeth.utils.encrypt(output_note1_str, pk_bob, eph_sk_bob)
    ciphertext2 = zeth.utils.encrypt(output_note2_str, pk_bob, eph_sk_bob)

    # get the ephemeral public key of the sender in bytes
    eph_pk_sender_bytes = eph_sk_bob.public_key.encode(encoder=nacl.encoding.RawEncoder)

    # Hash the pk_sender and cipher-texts
    ciphers = eph_pk_sender_bytes + ciphertext1 + ciphertext2
    hash_ciphers = sha256(ciphers).hexdigest()

    # Hash the proof
    proof = []
    for key in proof_json.keys():
        if key != "inputs":
            proof.extend(proof_json[key])
    hash_proof = sha256(zeth.utils.encode_to_hash(proof)).hexdigest()

    # Encode and hash the primary inputs
    encoded_inputs = zeth.grpc.encode_pub_input_to_hash(proof_json["inputs"])
    hash_inputs = sha256(encoded_inputs).hexdigest()

    # Compute the joinSplit signature
    joinsplit_sig = zeth.grpc.sign(joinsplit_keypair, hash_ciphers, hash_proof, hash_inputs)

    return zeth.contracts.mix(
        mixer_instance,
        eph_pk_sender_bytes,
        ciphertext1,
        ciphertext2,
        proof_json,
        joinsplit_keypair["vk"],
        joinsplit_sig,
        bob_eth_address,
        w3.toWei(BOB_DEPOSIT_ETH, 'ether'),
        4000000,
        zksnark
    )


def bob_to_charlie(
        test_grpc_endpoint,
        mixer_instance,
        mk_root,
        mk_path1,
        input_note1,
        input_address1,
        bob_eth_address,
        keystore,
        mk_tree_depth,
        zksnark):
    print(f"=== Bob transfers {BOB_TO_CHARLIE_ETH}ETH to Charlie from his funds on the mixer ===")

    # We generate a coin for Charlie (recipient1)
    charlie_apk = keystore["Charlie"]["addr_pk"]["apk"]
    # We generate a coin for Bob: the change (recipient2)
    bob_apk = keystore["Bob"]["addr_pk"]["apk"]
    # Bob is the sender
    bob_ask = keystore["Bob"]["addr_sk"]["ask"]

    # Create the an additional dummy input for the JoinSplit
    (input_note2, input_nullifier2, input_address2) = mock.get_dummy_input(
        bob_apk, bob_ask)
    dummy_mk_path = mock.get_dummy_merkle_path(mk_tree_depth)

    note1_value = zeth.utils.to_zeth_units(str(BOB_TO_CHARLIE_ETH), 'ether')
    note2_value = zeth.utils.to_zeth_units(str(BOB_TO_CHARLIE_CHANGE_ETH), 'ether')

    (output_note1, output_note2, proof_json, joinsplit_keypair) = \
        zeth.grpc.get_proof_joinsplit_2_by_2(
            test_grpc_endpoint,
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
            zeth.utils.int64_to_hex(note1_value),  # value output note 1
            zeth.utils.int64_to_hex(note2_value),  # value output note 2
            zero_units_hex,  # v_in
            zero_units_hex,  # v_out
            zksnark
        )

    output_note1_str = json.dumps(zeth.grpc.parse_zeth_note(output_note1))
    output_note2_str = json.dumps(zeth.grpc.parse_zeth_note(output_note2))

    # generate ephemeral ec25519 key
    eph_sk_bob = PrivateKey.generate()

    # construct pk objects from bytes
    pk_bob = zeth.utils.get_public_key_from_bytes(keystore["Bob"]["addr_pk"]["enc_pk"])
    pk_charlie = zeth.utils.get_public_key_from_bytes(keystore["Charlie"]["addr_pk"]["enc_pk"])

    # encrypt the coins
    # Bob is the recipient
    ciphertext1 = zeth.utils.encrypt(output_note1_str, pk_bob, eph_sk_bob)
    # Charlie is the recipient
    ciphertext2 = zeth.utils.encrypt(output_note2_str, pk_charlie, eph_sk_bob)
    pk_sender = eph_sk_bob.public_key.encode(encoder=nacl.encoding.RawEncoder)

    # Hash the pk_sender and cipher-texts
    ciphers = pk_sender + ciphertext1 + ciphertext2
    hash_ciphers = sha256(ciphers).hexdigest()

    # Hash the proof
    proof = []
    for key in proof_json.keys():
        if key != "inputs":
            proof.extend(proof_json[key])
    hash_proof = sha256(zeth.utils.encode_to_hash(proof)).hexdigest()

    # Encode and hash the primary inputs
    encoded_inputs = zeth.grpc.encode_pub_input_to_hash(proof_json["inputs"])
    hash_inputs = sha256(encoded_inputs).hexdigest()

    # Compute the joinSplit signature
    joinsplit_sig = zeth.grpc.sign(joinsplit_keypair, hash_ciphers, hash_proof, hash_inputs)

    return zeth.contracts.mix(
        mixer_instance,
        pk_sender,
        ciphertext1,
        ciphertext2,
        proof_json,
        joinsplit_keypair["vk"],
        joinsplit_sig,
        bob_eth_address,
        # Pay an arbitrary amount (1 wei here) that will be refunded since the
        # `mix` function is payable
        w3.toWei(1, 'wei'),
        4000000,
        zksnark
    )


def charlie_withdraw(
        test_grpc_endpoint,
        mixer_instance,
        mk_root,
        mk_path1,
        input_note1,
        input_address1,
        charlie_eth_address,
        keystore,
        mk_tree_depth,
        zksnark):
    print(f" === Charlie withdraws {CHARLIE_WITHDRAW_ETH}ETH from his funds on the Mixer ===")

    charlie_apk = keystore["Charlie"]["addr_pk"]["apk"]
    charlie_ask = keystore["Charlie"]["addr_sk"]["ask"]

    # Create the an additional dummy input for the JoinSplit
    (input_note2, input_nullifier2, input_address2) = mock.get_dummy_input(
        charlie_apk, charlie_ask)
    dummy_mk_path = mock.get_dummy_merkle_path(mk_tree_depth)

    note1_value = zeth.utils.to_zeth_units(str(CHARLIE_WITHDRAW_CHANGE_ETH), 'ether')
    v_out = zeth.utils.to_zeth_units(str(CHARLIE_WITHDRAW_ETH), 'ether')

    (output_note1, output_note2, proof_json, joinsplit_keypair) = \
        zeth.grpc.get_proof_joinsplit_2_by_2(
            test_grpc_endpoint,
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
            zeth.utils.int64_to_hex(note1_value),  # value output note 1
            zero_units_hex,  # value output note 2
            zero_units_hex,  # v_in
            zeth.utils.int64_to_hex(v_out),  # v_out
            zksnark
        )

    output_note1_str = json.dumps(zeth.grpc.parse_zeth_note(output_note1))
    output_note2_str = json.dumps(zeth.grpc.parse_zeth_note(output_note2))

    # generate ephemeral ec25519 key
    eph_sk_charlie = PrivateKey.generate()

    # construct pk object from bytes
    pk_charlie = zeth.utils.get_public_key_from_bytes(
        keystore["Charlie"]["addr_pk"]["enc_pk"])

    # encrypt the coins
    # Charlie is the recipient
    ciphertext1 = zeth.utils.encrypt(output_note1_str, pk_charlie, eph_sk_charlie)
    # Charlie is the recipient
    ciphertext2 = zeth.utils.encrypt(output_note2_str, pk_charlie, eph_sk_charlie)
    pk_sender = eph_sk_charlie.public_key.encode(encoder=nacl.encoding.RawEncoder)

    # Hash the pk_sender and cipher-texts
    ciphers = pk_sender + ciphertext1 + ciphertext2
    hash_ciphers = sha256(ciphers).hexdigest()

    # Hash the proof
    proof = []
    for key in proof_json.keys():
        if key != "inputs":
            proof.extend(proof_json[key])
    hash_proof = sha256(zeth.utils.encode_to_hash(proof)).hexdigest()

    # Encode and hash the primary inputs
    encoded_inputs = zeth.grpc.encode_pub_input_to_hash(proof_json["inputs"])
    hash_inputs = sha256(encoded_inputs).hexdigest()

    # Compute the joinSplit signature
    joinsplit_sig = zeth.grpc.sign(joinsplit_keypair, hash_ciphers, hash_proof, hash_inputs)

    return zeth.contracts.mix(
        mixer_instance,
        pk_sender,
        ciphertext1,
        ciphertext2,
        proof_json,
        joinsplit_keypair["vk"],
        joinsplit_sig,
        charlie_eth_address,
        # Pay an arbitrary amount (1 wei here) that will be refunded since the
        # `mix` function is payable
        w3.toWei(1, 'wei'),
        4000000,
        zksnark
    )


def charlie_double_withdraw(
        test_grpc_endpoint,
        mixer_instance,
        mk_root,
        mk_path1,
        input_note1,
        input_address1,
        charlie_eth_address,
        keystore,
        mk_tree_depth,
        zksnark):
    """
    Charlie tries to carry out a double spending by modifying the value of the
    nullifier of the previous payment
    """
    print(
        f" === Charlie attempts to withdraw {CHARLIE_WITHDRAW_ETH}ETH once more " +
        "(double spend) one of his note on the Mixer ===")

    charlie_apk = keystore["Charlie"]["addr_pk"]["apk"]
    charlie_ask = keystore["Charlie"]["addr_sk"]["ask"]

    # Create the an additional dummy input for the JoinSplit
    (input_note2, input_nullifier2, input_address2) = \
        mock.get_dummy_input(charlie_apk, charlie_ask)
    dummy_mk_path = mock.get_dummy_merkle_path(mk_tree_depth)

    note1_value = zeth.utils.to_zeth_units(str(CHARLIE_WITHDRAW_CHANGE_ETH), 'ether')
    v_out = zeth.utils.to_zeth_units(str(CHARLIE_WITHDRAW_ETH), 'ether')

    (output_note1, output_note2, proof_json, joinsplit_keypair) = \
        zeth.grpc.get_proof_joinsplit_2_by_2(
            test_grpc_endpoint,
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
            zeth.utils.int64_to_hex(note1_value),  # value output note 1
            zero_units_hex,  # value output note 2
            zero_units_hex,  # v_in
            zeth.utils.int64_to_hex(v_out),  # v_out
            zksnark
        )

    # ### ATTACK BLOCK
    # Add malicious nullifiers (located at index 2 and 4 in the array of inputs)
    # See: https://github.com/clearmatics/zeth/issues/38
    r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    print("proof_json => ", proof_json)
    print("proof_json[inputs][2] => ", proof_json["inputs"][2])
    print("proof_json[inputs][4] => ", proof_json["inputs"][4])
    proof_json["inputs"][2] = hex(int(proof_json["inputs"][2], 16) + r)
    proof_json["inputs"][4] = hex(int(proof_json["inputs"][4], 16) + r)
    # ### ATTACK BLOCK

    output_note1_str = json.dumps(zeth.grpc.parse_zeth_note(output_note1))
    output_note2_str = json.dumps(zeth.grpc.parse_zeth_note(output_note2))

    # generate ephemeral ec25519 key
    eph_sk_charlie = PrivateKey.generate()

    # construct pk object from bytes
    pk_charlie = zeth.utils.get_public_key_from_bytes(keystore["Charlie"]["addr_pk"]["enc_pk"])

    # encrypt the coins
    # Charlie is the recipient
    ciphertext1 = zeth.utils.encrypt(output_note1_str, pk_charlie, eph_sk_charlie)
    # Charlie is the recipient
    ciphertext2 = zeth.utils.encrypt(output_note2_str, pk_charlie, eph_sk_charlie)
    pk_sender = eph_sk_charlie.public_key.encode(encoder=nacl.encoding.RawEncoder)

    # Hash the pk_sender and cipher-texts
    ciphers = pk_sender + ciphertext1 + ciphertext2
    hash_ciphers = sha256(ciphers).hexdigest()

    # Hash the proof
    proof = []
    for key in proof_json.keys():
        if key != "inputs":
            proof.extend(proof_json[key])
    hash_proof = sha256(zeth.utils.encode_to_hash(proof)).hexdigest()

    # Encode and hash the primary inputs
    encoded_inputs = zeth.grpc.encode_pub_input_to_hash(proof_json["inputs"])
    hash_inputs = sha256(encoded_inputs).hexdigest()

    # Compute the joinSplit signature
    joinsplit_sig = zeth.grpc.sign(
        joinsplit_keypair, hash_ciphers, hash_proof, hash_inputs)

    return zeth.contracts.mix(
        mixer_instance,
        pk_sender,
        ciphertext1,
        ciphertext2,
        proof_json,
        joinsplit_keypair["vk"],
        joinsplit_sig,
        charlie_eth_address,
        # Pay an arbitrary amount (1 wei here) that will be refunded since the
        # `mix` function is payable
        w3.toWei(1, 'wei'),
        4000000,
        zksnark
    )
