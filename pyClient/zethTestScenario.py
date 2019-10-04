import zethUtils
import zethGRPC
import zethMock
import zethContracts

import json
from hashlib import sha256

import nacl.utils
from nacl.public import PrivateKey

from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider

w3 = Web3(HTTPProvider("http://localhost:8545"))

zero_wei_hex = "0000000000000000"

def bob_deposit(test_grpc_endpoint, mixer_instance, mk_root, bob_eth_address, keystore, mk_tree_depth, zksnark):
    print("=== Bob deposits 4 ETH for himself and splits his deposited funds into note1: 2ETH, note2: 2ETH ===")
    bob_apk = keystore["Bob"]["AddrPk"]["aPK"]
    bob_ask = keystore["Bob"]["AddrSk"]["aSK"]
    # Create the JoinSplit dummy inputs for the deposit
    (input_note1, input_nullifier1, input_address1) = zethMock.getDummyInput(bob_apk, bob_ask)
    (input_note2, input_nullifier2, input_address2) = zethMock.getDummyInput(bob_apk, bob_ask)
    dummy_mk_path = zethMock.getDummyMerklePath(mk_tree_depth)

    (output_note1, output_note2, proof_json, joinsplit_keypair) = zethGRPC.getProofJoinsplit2By2(
        test_grpc_endpoint,
        mk_root,
        input_note1,
        input_address1,
        dummy_mk_path,
        input_note2,
        input_address2,
        dummy_mk_path,
        bob_ask, # sender
        bob_apk, # recipient1
        bob_apk, # recipient2
        zethGRPC.int64ToHexadecimal(Web3.toWei('2', 'ether')), # value output note 1
        zethGRPC.int64ToHexadecimal(Web3.toWei('2', 'ether')), # value output note 2
        zethGRPC.int64ToHexadecimal(Web3.toWei('4', 'ether')), # v_in
        zero_wei_hex, # v_out
        zksnark
    )

    output_note1_str = json.dumps(zethGRPC.parseZethNote(output_note1))
    output_note2_str = json.dumps(zethGRPC.parseZethNote(output_note2))

    # generate ephemeral ec25519 key
    eph_sk_bob = PrivateKey.generate()

    # construct pk object from bytes
    pk_bob = zethUtils.get_public_key_from_bytes(keystore["Bob"]["AddrPk"]["encPK"])

    # encrypt the coins
    ciphertext1 = zethUtils.encrypt(output_note1_str, pk_bob, eph_sk_bob)
    ciphertext2 = zethUtils.encrypt(output_note2_str, pk_bob, eph_sk_bob)

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
    hash_proof = sha256(zethGRPC.encodeToHash(proof)).hexdigest()

    # Encode and hash the primary inputs
    encoded_inputs = zethGRPC.encodeInputToHash(proof_json["inputs"])
    hash_inputs = sha256(encoded_inputs).hexdigest()

    # Compute the joinSplit signature
    joinsplit_sig = zethGRPC.sign(joinsplit_keypair, hash_ciphers, hash_proof, hash_inputs)

    return zethContracts.mix(
        mixer_instance,
        eph_pk_sender_bytes,
        ciphertext1,
        ciphertext2,
        proof_json,
        joinsplit_keypair["vk"],
        joinsplit_sig,
        bob_eth_address,
        w3.toWei(4, 'ether'),
        4000000,
        zksnark
    )

def bob_to_charlie(test_grpc_endpoint, mixer_instance, mk_root, mk_path1, input_note1, input_address1, bob_eth_address, keystore, mk_tree_depth, zksnark):
    print("=== Bob transfers 1ETH to Charlie from his funds on the mixer ===")

    charlie_apk = keystore["Charlie"]["AddrPk"]["aPK"] # We generate a coin for Charlie (recipient1)
    bob_apk = keystore["Bob"]["AddrPk"]["aPK"] # We generate a coin for Bob: the change (recipient2)
    bob_ask = keystore["Bob"]["AddrSk"]["aSK"] # Bob is the sender

    # Create the an additional dummy input for the JoinSplit
    (input_note2, input_nullifier2, input_address2) = zethMock.getDummyInput(bob_apk, bob_ask)
    dummy_mk_path = zethMock.getDummyMerklePath(mk_tree_depth)

    (output_note1, output_note2, proof_json, joinsplit_keypair) = zethGRPC.getProofJoinsplit2By2(
        test_grpc_endpoint,
        mk_root,
        input_note1,
        input_address1,
        mk_path1,
        input_note2,
        input_address2,
        dummy_mk_path,
        bob_ask, # sender
        bob_apk, # recipient1 (change)
        charlie_apk, # recipient2 (transfer)
        zethGRPC.int64ToHexadecimal(Web3.toWei('1', 'ether')), # value output note 1
        zethGRPC.int64ToHexadecimal(Web3.toWei('1', 'ether')), # value output note 2
        zero_wei_hex, # v_in
        zero_wei_hex, # v_out
        zksnark
    )

    output_note1_str = json.dumps(zethGRPC.parseZethNote(output_note1))
    output_note2_str = json.dumps(zethGRPC.parseZethNote(output_note2))

    # generate ephemeral ec25519 key
    eph_sk_bob = PrivateKey.generate()

    # construct pk objects from bytes
    pk_bob = zethUtils.get_public_key_from_bytes(keystore["Bob"]["AddrPk"]["encPK"])
    pk_charlie = zethUtils.get_public_key_from_bytes(keystore["Charlie"]["AddrPk"]["encPK"])

    # encrypt the coins
    ciphertext1 = zethUtils.encrypt(output_note1_str, pk_bob, eph_sk_bob) # Bob is the recipient
    ciphertext2 = zethUtils.encrypt(output_note2_str, pk_charlie, eph_sk_bob) # Charlie is the recipient
    pk_sender = eph_sk_bob.public_key.encode(encoder=nacl.encoding.RawEncoder)

    # Hash the pk_sender and cipher-texts
    ciphers = pk_sender + ciphertext1 + ciphertext2
    hash_ciphers = sha256(ciphers).hexdigest()

    # Hash the proof
    proof = []
    for key in proof_json.keys():
        if key != "inputs":
            proof.extend(proof_json[key])
    hash_proof = sha256(zethGRPC.encodeToHash(proof)).hexdigest()

    # Encode and hash the primary inputs
    encoded_inputs = zethGRPC.encodeInputToHash(proof_json["inputs"])
    hash_inputs = sha256(encoded_inputs).hexdigest()

    # Compute the joinSplit signature
    joinsplit_sig = zethGRPC.sign(joinsplit_keypair, hash_ciphers, hash_proof, hash_inputs)

    return zethContracts.mix(
        mixer_instance,
        pk_sender,
        ciphertext1,
        ciphertext2,
        proof_json,
        joinsplit_keypair["vk"],
        joinsplit_sig,
        bob_eth_address,
        w3.toWei(1, 'wei'), # Pay an arbitrary amount (1 wei here) that will be refunded since the `mix` function is payable
        4000000,
        zksnark
    )

def charlie_withdraw(test_grpc_endpoint, mixer_instance, mk_root, mk_path1, input_note1, input_address1, charlie_eth_address, keystore, mk_tree_depth, zksnark):
    print(" === Charlie withdraws 0.9 from his funds on the Mixer ===")

    charlie_apk = keystore["Charlie"]["AddrPk"]["aPK"]
    charlie_ask = keystore["Charlie"]["AddrSk"]["aSK"]

    # Create the an additional dummy input for the JoinSplit
    (input_note2, input_nullifier2, input_address2) = zethMock.getDummyInput(charlie_apk, charlie_ask)
    dummy_mk_path = zethMock.getDummyMerklePath(mk_tree_depth)

    (output_note1, output_note2, proof_json, joinsplit_keypair) = zethGRPC.getProofJoinsplit2By2(
        test_grpc_endpoint,
        mk_root,
        input_note1,
        input_address1,
        mk_path1,
        input_note2,
        input_address2,
        dummy_mk_path,
        charlie_ask, # sender
        charlie_apk, # recipient1
        charlie_apk, # recipient2
        zethGRPC.int64ToHexadecimal(Web3.toWei('0.1', 'ether')), # value output note 1
        zero_wei_hex, # value output note 2
        zero_wei_hex, # v_in
        zethGRPC.int64ToHexadecimal(Web3.toWei('0.9', 'ether')), # v_out
        zksnark
    )

    output_note1_str = json.dumps(zethGRPC.parseZethNote(output_note1))
    output_note2_str = json.dumps(zethGRPC.parseZethNote(output_note2))

    # generate ephemeral ec25519 key
    eph_sk_charlie = PrivateKey.generate()

    # construct pk object from bytes
    pk_charlie = zethUtils.get_public_key_from_bytes(keystore["Charlie"]["AddrPk"]["encPK"])

    # encrypt the coins
    ciphertext1 = zethUtils.encrypt(output_note1_str, pk_charlie, eph_sk_charlie) # Charlie is the recipient
    ciphertext2 = zethUtils.encrypt(output_note2_str, pk_charlie, eph_sk_charlie) # Charlie is the recipient
    pk_sender = eph_sk_charlie.public_key.encode(encoder=nacl.encoding.RawEncoder)

    # Hash the pk_sender and cipher-texts
    ciphers = pk_sender + ciphertext1 + ciphertext2
    hash_ciphers = sha256(ciphers).hexdigest()

    # Hash the proof
    proof = []
    for key in proof_json.keys():
        if key != "inputs":
            proof.extend(proof_json[key])
    hash_proof = sha256(zethGRPC.encodeToHash(proof)).hexdigest()

    # Encode and hash the primary inputs
    encoded_inputs = zethGRPC.encodeInputToHash(proof_json["inputs"])
    hash_inputs = sha256(encoded_inputs).hexdigest()

    # Compute the joinSplit signature
    joinsplit_sig = zethGRPC.sign(joinsplit_keypair, hash_ciphers, hash_proof, hash_inputs)

    return zethContracts.mix(
        mixer_instance,
        pk_sender,
        ciphertext1,
        ciphertext2,
        proof_json,
        joinsplit_keypair["vk"],
        joinsplit_sig,
        charlie_eth_address,
        w3.toWei(1, 'wei'), # Pay an arbitrary amount (1 wei here) that will be refunded since the `mix` function is payable
        4000000,
        zksnark
    )

# Charlie tries to carry out a double spending by modifying the value of the nullifier of the previous payment
def charlie_double_withdraw(test_grpc_endpoint, mixer_instance, mk_root, mk_path1, input_note1, input_address1, charlie_eth_address, keystore, mk_tree_depth, zksnark):
    print(" === Charlie attempts to withdraw 0.9 once more (doubke spend) from his funds on the Mixer ===")

    charlie_apk = keystore["Charlie"]["AddrPk"]["aPK"]
    charlie_ask = keystore["Charlie"]["AddrSk"]["aSK"]

    # Create the an additional dummy input for the JoinSplit
    (input_note2, input_nullifier2, input_address2) = zethMock.getDummyInput(charlie_apk, charlie_ask)
    dummy_mk_path = zethMock.getDummyMerklePath(mk_tree_depth)

    (output_note1, output_note2, proof_json, joinsplit_keypair) = zethGRPC.getProofJoinsplit2By2(
        test_grpc_endpoint,
        mk_root,
        input_note1,
        input_address1,
        mk_path1,
        input_note2,
        input_address2,
        dummy_mk_path,
        charlie_ask, # sender
        charlie_apk, # recipient1
        charlie_apk, # recipient2
        zethGRPC.int64ToHexadecimal(Web3.toWei('0.1', 'ether')), # value output note 1
        zero_wei_hex, # value output note 2
        zero_wei_hex, # v_in
        zethGRPC.int64ToHexadecimal(Web3.toWei('0.9', 'ether')), # v_out
        zksnark
    )

    ##### ATTACK BLOCK
    # Add malicious nullifiers (located at index 2 and 4 in the array of inputs)
    r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    print("proof_json => ", proof_json)
    print("proof_json[inputs][2] => ", proof_json["inputs"][2])
    print("proof_json[inputs][4] => ", proof_json["inputs"][4])
    proof_json["inputs"][2] = hex(int(proof_json["inputs"][2], 16) + r)
    proof_json["inputs"][4] = hex(int(proof_json["inputs"][4], 16) + r)
    ##### ATTACK BLOCK

    output_note1_str = json.dumps(zethGRPC.parseZethNote(output_note1))
    output_note2_str = json.dumps(zethGRPC.parseZethNote(output_note2))

    # generate ephemeral ec25519 key
    eph_sk_charlie = PrivateKey.generate()

    # construct pk object from bytes
    pk_charlie = zethUtils.get_public_key_from_bytes(keystore["Charlie"]["AddrPk"]["encPK"])

    # encrypt the coins
    ciphertext1 = zethUtils.encrypt(output_note1_str, pk_charlie, eph_sk_charlie) # Charlie is the recipient
    ciphertext2 = zethUtils.encrypt(output_note2_str, pk_charlie, eph_sk_charlie) # Charlie is the recipient
    pk_sender = eph_sk_charlie.public_key.encode(encoder=nacl.encoding.RawEncoder)

    # Hash the pk_sender and cipher-texts
    ciphers = pk_sender + ciphertext1 + ciphertext2
    hash_ciphers = sha256(ciphers).hexdigest()

    # Hash the proof
    proof = []
    for key in proof_json.keys():
        if key != "inputs":
            proof.extend(proof_json[key])
    hash_proof = sha256(zethGRPC.encodeToHash(proof)).hexdigest()

    # Encode and hash the primary inputs
    encoded_inputs = zethGRPC.encodeInputToHash(proof_json["inputs"])
    hash_inputs = sha256(encoded_inputs).hexdigest()

    # Compute the joinSplit signature
    joinsplit_sig = zethGRPC.sign(joinsplit_keypair, hash_ciphers, hash_proof, hash_inputs)

    return zethContracts.mix(
        mixer_instance,
        pk_sender,
        ciphertext1,
        ciphertext2,
        proof_json,
        joinsplit_keypair["vk"],
        joinsplit_sig,
        charlie_eth_address,
        w3.toWei(1, 'wei'), # Pay an arbitrary amount (1 wei here) that will be refunded since the `mix` function is payable
        4000000,
        zksnark
    )
