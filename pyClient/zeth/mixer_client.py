#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
import zeth.contracts as contracts
import zeth.constants as constants
from zeth.zeth_address import ZethAddressPub, ZethAddress
from zeth.ownership import OwnershipPublicKey, OwnershipSecretKey, \
    OwnershipKeyPair, ownership_key_as_hex
from zeth.encryption import \
    EncryptionPublicKey, EncryptionSecretKey, generate_encryption_keypair, \
    encode_encryption_public_key, encrypt, decrypt
from zeth.merkle_tree import MerkleTree, compute_merkle_path
import zeth.signing as signing
from zeth.timer import Timer
from zeth.zksnark import \
    IZKSnarkProvider, get_zksnark_provider, GenericProof, GenericVerificationKey
from zeth.utils import EtherValue, get_trusted_setup_dir, \
    hex_digest_to_binary_string, digest_to_binary_string, int64_to_hex, \
    message_to_bytes, eth_address_to_bytes, eth_uint256_to_int, to_zeth_units
from zeth.prover_client import ProverClient
from api.zeth_messages_pb2 import ZethNote, JoinsplitInput, ProofInputs

import os
import json
from Crypto import Random
from hashlib import blake2s, sha256
from typing import Tuple, Dict, List, Callable, Optional, Any


ZERO_UNITS_HEX = "0000000000000000"


# JoinSplit Signature Keys definitions
JoinsplitSigVerificationKey = signing.SigningVerificationKey
JoinsplitSigSecretKey = signing.SigningSecretKey
JoinsplitSigKeyPair = signing.SigningKeyPair


ComputeHSigCB = Callable[[bytes, bytes, JoinsplitSigVerificationKey], bytes]


def blake2s_compress(left: bytes, right: bytes) -> bytes:
    """
    Execute blake2s as a compression function, ensuring that the input is of
    the correct length. (The case len(left) != len(right) is supported, but the
    total input length must be 64 bytes).
    """
    assert len(left) + len(right) == 64
    blake = blake2s()
    blake.update(left)
    blake.update(right)
    return blake.digest()


def blake2s_compress_pad_right64(left256: bytes, right64: bytes) -> bytes:
    """
    As blake2s_compress, but pad right from 64 bits to 256.
    """
    assert len(left256) == 32
    assert len(right64) == 8
    blake = blake2s()
    blake.update(left256)
    blake.update(constants.COMMITMENT_VALUE_PADDING)
    blake.update(right64)
    return blake.digest()


class JoinsplitInputNote:
    """
    A ZethNote, along with the nullifier and location in Merkle tree.
    """

    def __init__(self, note: ZethNote, nullifier: str, merkle_location: int):
        self.note = note
        self.nullifier = nullifier
        self.merkle_location = merkle_location


def create_zeth_notes(
        phi: str,
        hsig: bytes,
        output0: Tuple[OwnershipPublicKey, int],
        output1: Tuple[OwnershipPublicKey, int]
) -> Tuple[ZethNote, ZethNote]:
    """
    Create two ordered ZethNotes. This function is used to generate new output
    notes.
    """
    (recipient0, value0) = output0
    (recipient1, value1) = output1

    rho0 = _compute_rho_i(phi, hsig, 0)
    trap_r0 = trap_r_randomness()
    note0 = ZethNote(
        apk=ownership_key_as_hex(recipient0),
        value=int64_to_hex(value0),
        rho=rho0.hex(),
        trap_r=trap_r0)

    rho1 = _compute_rho_i(phi, hsig, 1)
    trap_r1 = trap_r_randomness()
    note1 = ZethNote(
        apk=ownership_key_as_hex(recipient1),
        value=int64_to_hex(value1),
        rho=rho1.hex(),
        trap_r=trap_r1)

    return note0, note1


def zeth_note_to_json_dict(zeth_note_grpc_obj: ZethNote) -> Dict[str, str]:
    return {
        "a_pk": zeth_note_grpc_obj.apk,
        "value": zeth_note_grpc_obj.value,
        "rho": zeth_note_grpc_obj.rho,
        "trap_r": zeth_note_grpc_obj.trap_r,
    }


def zeth_note_from_json_dict(parsed_zeth_note: Dict[str, str]) -> ZethNote:
    note = ZethNote(
        apk=parsed_zeth_note["a_pk"],
        value=parsed_zeth_note["value"],
        rho=parsed_zeth_note["rho"],
        trap_r=parsed_zeth_note["trap_r"]
    )
    return note


def compute_commitment(zeth_note: ZethNote) -> bytes:
    """
    Used by the recipient of a payment to recompute the commitment and check
    the membership in the tree to confirm the validity of a payment
    """
    # inner_k = blake2s(a_pk || rho)
    inner_k = blake2s_compress(
        bytes.fromhex(zeth_note.apk),
        bytes.fromhex(zeth_note.rho))

    # outer_k = blake2s(r || [inner_k]_128)
    inner_k_128 = inner_k[0:16]  # 128 bits = 16 hex chars
    outer_k = blake2s_compress(bytes.fromhex(zeth_note.trap_r), inner_k_128)

    # cm = blake2s(outer_k || zero_pad_64_to_256(value))
    cm = blake2s_compress_pad_right64(outer_k, bytes.fromhex(zeth_note.value))

    cm_field = int.from_bytes(cm, byteorder="big") % constants.ZETH_PRIME
    return cm_field.to_bytes(int(constants.DIGEST_LENGTH/8), byteorder="big")


def compute_nullifier(
        zeth_note: ZethNote,
        spending_authority_ask: OwnershipSecretKey) -> bytes:
    """
    Returns nf = blake2s(1110 || [a_sk]_252 || rho)
    """
    binary_ask = digest_to_binary_string(spending_authority_ask)
    first_252bits_ask = binary_ask[:252]
    left_leg_bin = "1110" + first_252bits_ask
    left_leg = int(left_leg_bin, 2).to_bytes(32, byteorder='big')
    blake_hash = blake2s()
    blake_hash.update(left_leg)
    blake_hash.update(bytes.fromhex(zeth_note.rho))
    return blake_hash.digest()


def create_joinsplit_input(
        merkle_path: List[str],
        address: int,
        note: ZethNote,
        a_sk: OwnershipSecretKey,
        nullifier: bytes) -> JoinsplitInput:
    return JoinsplitInput(
        merkle_path=merkle_path,
        address=address,
        note=note,
        spending_ask=ownership_key_as_hex(a_sk),
        nullifier=nullifier.hex())


def write_verification_key(vk_json: GenericVerificationKey) -> None:
    """
    Writes the verification key (object) in a json file
    """
    setup_dir = get_trusted_setup_dir()
    filename = os.path.join(setup_dir, "vk.json")
    with open(filename, 'w') as outfile:
        json.dump(vk_json, outfile)


def get_dummy_rho() -> str:
    return bytes(Random.get_random_bytes(32)).hex()


def get_dummy_input_and_address(
        a_pk: OwnershipPublicKey) -> Tuple[int, ZethNote]:
    """
    Create a zeth note and address, for use as circuit inputs where there is no
    real input.
    """
    dummy_note = ZethNote(
        apk=ownership_key_as_hex(a_pk),
        value=ZERO_UNITS_HEX,
        rho=get_dummy_rho(),
        trap_r=trap_r_randomness())
    # Note that the Merkle path is not fully checked against the root by the
    # circuit since the note value is 0. Hence the address used here is
    # arbitrary.
    dummy_note_address = 0
    return (dummy_note_address, dummy_note)


def compute_joinsplit2x2_inputs(
        mk_root: bytes,
        input0: Tuple[int, ZethNote],
        mk_path0: List[str],
        input1: Tuple[int, ZethNote],
        mk_path1: List[str],
        sender_ask: OwnershipSecretKey,
        output0: Tuple[OwnershipPublicKey, int],
        output1: Tuple[OwnershipPublicKey, int],
        public_in_value_zeth_units: int,
        public_out_value_zeth_units: int,
        sign_vk: JoinsplitSigVerificationKey,
        compute_h_sig_cb: Optional[ComputeHSigCB] = None
) -> ProofInputs:
    """
    Create a ProofInput object for joinsplit parameters
    """
    (input_address0, input_note0) = input0
    (input_address1, input_note1) = input1

    input_nullifier0 = compute_nullifier(input_note0, sender_ask)
    input_nullifier1 = compute_nullifier(input_note1, sender_ask)
    js_inputs: List[JoinsplitInput] = [
        create_joinsplit_input(
            mk_path0, input_address0, input_note0, sender_ask, input_nullifier0),
        create_joinsplit_input(
            mk_path1, input_address1, input_note1, sender_ask, input_nullifier1)
    ]

    # Use the specified or default h_sig computation
    compute_h_sig_cb = compute_h_sig_cb or compute_h_sig
    h_sig = compute_h_sig_cb(
        input_nullifier0,
        input_nullifier1,
        sign_vk)
    phi = _transaction_randomness()

    output_note0, output_note1 = create_zeth_notes(
        phi,
        h_sig,
        output0,
        output1)

    js_outputs = [
        output_note0,
        output_note1
    ]

    return ProofInputs(
        mk_root=mk_root.hex(),
        js_inputs=js_inputs,
        js_outputs=js_outputs,
        pub_in_value=int64_to_hex(public_in_value_zeth_units),
        pub_out_value=int64_to_hex(public_out_value_zeth_units),
        h_sig=h_sig.hex(),
        phi=phi)


class MixerClient:
    """
    Interface to operations on the Mixer contract.
    """
    def __init__(
            self,
            web3: Any,
            prover_client: ProverClient,
            mixer_instance: Any,
            zksnark: IZKSnarkProvider):
        self._prover_client = prover_client
        self.web3 = web3
        self._zksnark = zksnark
        self.mixer_instance = mixer_instance

    @staticmethod
    def open(
            web3: Any,
            prover_server_endpoint: str,
            mixer_instance: Any) -> MixerClient:
        """
        Create a client for an existing Zeth deployment.
        """
        return MixerClient(
            web3,
            ProverClient(prover_server_endpoint),
            mixer_instance,
            get_zksnark_provider(constants.ZKSNARK_DEFAULT))

    @staticmethod
    def deploy(
            web3: Any,
            prover_server_endpoint: str,
            deployer_eth_address: str,
            token_address: Optional[str] = None,
            deploy_gas: Optional[EtherValue] = None,
            zksnark: Optional[IZKSnarkProvider] = None) -> MixerClient:
        """
        Deploy Zeth contracts.
        """
        print("[INFO] 1. Fetching verification key from the proving server")
        zksnark = zksnark or get_zksnark_provider(constants.ZKSNARK_DEFAULT)
        prover_client = ProverClient(prover_server_endpoint)
        vk_obj = prover_client.get_verification_key()
        vk_json = zksnark.parse_verification_key(vk_obj)
        deploy_gas = deploy_gas or \
            EtherValue(constants.DEPLOYMENT_GAS_WEI, 'wei')

        print("[INFO] 2. Received VK, writing verification key...")
        write_verification_key(vk_json)

        print("[INFO] 3. VK written, deploying smart contracts...")
        mixer_interface = contracts.compile_mixer(zksnark)
        mixer_instance = contracts.deploy_mixer(
            web3,
            constants.ZETH_MERKLE_TREE_DEPTH,
            mixer_interface,
            vk_json,
            deployer_eth_address,
            deploy_gas.wei,
            token_address or "0x0000000000000000000000000000000000000000",
            zksnark)
        return MixerClient(
            web3,
            prover_client,
            mixer_instance,
            zksnark)

    def deposit(
            self,
            mk_tree: MerkleTree,
            zeth_address: ZethAddress,
            sender_eth_address: str,
            eth_amount: EtherValue,
            outputs: Optional[List[Tuple[ZethAddressPub, EtherValue]]] = None,
            tx_value: Optional[EtherValue] = None
    ) -> str:
        if not outputs or len(outputs) == 0:
            outputs = [(zeth_address.addr_pk, eth_amount)]
        return self.joinsplit(
            mk_tree,
            sender_ownership_keypair=zeth_address.ownership_keypair(),
            sender_eth_address=sender_eth_address,
            inputs=[],
            outputs=outputs,
            v_in=eth_amount,
            v_out=EtherValue(0),
            tx_value=tx_value)

    def joinsplit(
            self,
            mk_tree: MerkleTree,
            sender_ownership_keypair: OwnershipKeyPair,
            sender_eth_address: str,
            inputs: List[Tuple[int, ZethNote]],
            outputs: List[Tuple[ZethAddressPub, EtherValue]],
            v_in: EtherValue,
            v_out: EtherValue,
            tx_value: Optional[EtherValue] = None,
            compute_h_sig_cb: Optional[ComputeHSigCB] = None) -> str:
        mix_params = self.create_mix_parameters(
            mk_tree,
            sender_ownership_keypair,
            sender_eth_address,
            inputs,
            outputs,
            v_in,
            v_out,
            compute_h_sig_cb)

        # By default transfer exactly v_in, otherwise allow caller to manually
        # specify.
        tx_value = tx_value or v_in
        return self.mix(
            mix_params,
            sender_eth_address,
            tx_value.wei,
            constants.DEFAULT_MIX_GAS_WEI)

    def create_mix_parameters(
            self,
            mk_tree: MerkleTree,
            sender_ownership_keypair: OwnershipKeyPair,
            sender_eth_address: str,
            inputs: List[Tuple[int, ZethNote]],
            outputs: List[Tuple[ZethAddressPub, EtherValue]],
            v_in: EtherValue,
            v_out: EtherValue,
            compute_h_sig_cb: Optional[ComputeHSigCB] = None
    ) -> contracts.MixParameters:

        assert len(inputs) <= constants.JS_INPUTS
        assert len(outputs) <= constants.JS_OUTPUTS

        sender_a_sk = sender_ownership_keypair.a_sk
        sender_a_pk = sender_ownership_keypair.a_pk
        inputs = \
            inputs + \
            [get_dummy_input_and_address(sender_a_pk)
             for _ in range(constants.JS_INPUTS - len(inputs))]
        mk_root = mk_tree.get_root()
        mk_paths = [compute_merkle_path(addr, mk_tree) for addr, _ in inputs]

        # Generate output notes and proof.  Dummy outputs are constructed with
        # value 0 to an invalid ZethAddressPub, formed from the senders
        # a_pk, and an ephemeral k_pk.
        dummy_k_pk = generate_encryption_keypair().k_pk
        dummy_addr_pk = ZethAddressPub(sender_a_pk, dummy_k_pk)
        outputs = \
            outputs + \
            [(dummy_addr_pk, EtherValue(0))
             for _ in range(constants.JS_OUTPUTS - len(outputs))]
        outputs_with_a_pk = \
            [(zeth_addr.a_pk, to_zeth_units(value))
             for (zeth_addr, value) in outputs]

        # Timer used to time proof-generation round trip time.
        timer = Timer.started()

        (output_note1, output_note2, proof_json, signing_keypair) = \
            self.get_proof_joinsplit_2_by_2(
                mk_root,
                inputs[0],
                mk_paths[0],
                inputs[1],
                mk_paths[1],
                sender_a_sk,
                outputs_with_a_pk[0],
                outputs_with_a_pk[1],
                to_zeth_units(v_in),
                to_zeth_units(v_out),
                compute_h_sig_cb)

        proof_gen_time_s = timer.elapsed_seconds()
        print(f"PROOF GEN ROUND TRIP: {proof_gen_time_s} seconds")

        # Encrypt the notes
        outputs_and_notes = zip(outputs, [output_note1, output_note2])
        output_notes_with_k_pk = \
            [(note, zeth_addr.k_pk)
             for ((zeth_addr, _), note) in outputs_and_notes]
        (sender_eph_pk, ciphertexts) = encrypt_notes(output_notes_with_k_pk)

        # Sign
        signature = joinsplit_sign(
            signing_keypair,
            sender_eth_address,
            sender_eph_pk,
            ciphertexts,
            proof_json)

        return contracts.MixParameters(
            proof_json,
            signing_keypair.vk,
            signature,
            sender_eph_pk,
            ciphertexts)

    def mix(
            self,
            mix_params: contracts.MixParameters,
            sender_eth_address: str,
            wei_pub_value: int,
            call_gas: int) -> str:
        return contracts.mix(
            self._zksnark,
            self.mixer_instance,
            mix_params,
            sender_eth_address,
            wei_pub_value,
            call_gas)

    def mix_call(
            self,
            mix_params: contracts.MixParameters,
            sender_eth_address: str,
            wei_pub_value: int,
            call_gas: int) -> bool:
        return contracts.mix_call(
            self._zksnark,
            self.mixer_instance,
            mix_params,
            sender_eth_address,
            wei_pub_value,
            call_gas)

    def get_proof_joinsplit_2_by_2(
            self,
            mk_root: bytes,
            input0: Tuple[int, ZethNote],
            mk_path0: List[str],
            input1: Tuple[int, ZethNote],
            mk_path1: List[str],
            sender_ask: OwnershipSecretKey,
            output0: Tuple[OwnershipPublicKey, int],
            output1: Tuple[OwnershipPublicKey, int],
            public_in_value_zeth_units: int,
            public_out_value_zeth_units: int,
            compute_h_sig_cb: Optional[ComputeHSigCB] = None
    ) -> Tuple[ZethNote, ZethNote, Dict[str, Any], JoinsplitSigKeyPair]:
        """
        Query the prover server to generate a proof for the given joinsplit
        parameters.
        """
        signing_keypair = signing.gen_signing_keypair()
        proof_input = compute_joinsplit2x2_inputs(
            mk_root,
            input0,
            mk_path0,
            input1,
            mk_path1,
            sender_ask,
            output0,
            output1,
            public_in_value_zeth_units,
            public_out_value_zeth_units,
            signing_keypair.vk,
            compute_h_sig_cb)
        proof_obj = self._prover_client.get_proof(proof_input)
        proof_json = self._zksnark.parse_proof(proof_obj)

        # Sanity check our unpacking code against the prover server output.
        pub_inputs = proof_json["inputs"]
        print(f"pub_inputs: {pub_inputs}")
        # pub_inputs_bytes = [bytes.fromhex(x) for x in pub_inputs]
        (v_in, v_out) = public_inputs_extract_public_values(pub_inputs)
        assert public_in_value_zeth_units == v_in
        assert public_out_value_zeth_units == v_out

        # We return the zeth notes to be able to spend them later
        # and the proof used to create them
        return (
            proof_input.js_outputs[0],  # pylint: disable=no-member
            proof_input.js_outputs[1],  # pylint: disable=no-member
            proof_json,
            signing_keypair)


def encrypt_notes(
        notes: List[Tuple[ZethNote, EncryptionPublicKey]]
) -> Tuple[EncryptionPublicKey, List[bytes]]:
    """
    Encrypts a set of output notes to be decrypted by the respective receivers.
    Returns the senders (ephemeral) public key (encoded as bytes) and the
    ciphertexts corresponding to each note.
    """
    # generate ephemeral ec25519 key
    eph_enc_key_pair = generate_encryption_keypair()
    eph_sk = eph_enc_key_pair.k_sk
    eph_pk = eph_enc_key_pair.k_pk

    def _encrypt_note(out_note: ZethNote, pub_key: EncryptionPublicKey) -> bytes:
        out_note_str = json.dumps(zeth_note_to_json_dict(out_note))
        return encrypt(out_note_str, pub_key, eph_sk)

    ciphertexts = [_encrypt_note(note, pk) for (note, pk) in notes]
    return (eph_pk, ciphertexts)


def receive_note(
        out_ev: contracts.MixOutputEvents,
        sender_k_pk: EncryptionPublicKey,
        receiver_k_sk: EncryptionSecretKey
) -> Optional[Tuple[bytes, ZethNote]]:
    """
    Given the receivers secret key, and the event data from a transaction
    (encrypted notes), decrypt any that are intended for the receiver. Return
    tuples `(<address-in-merkle-tree>, ZethNote)`. Callers should record the
    address-in-merkle-tree along with ZethNote information, for convenience
    when spending the notes.
    """
    try:
        plaintext = decrypt(out_ev.ciphertext, sender_k_pk, receiver_k_sk)
        return (
            out_ev.commitment,
            zeth_note_from_json_dict(json.loads(plaintext)))
    except Exception:
        return None


def _encode_proof_and_inputs(proof_json: GenericProof) -> Tuple[bytes, bytes]:
    """
    Given a proof object, compute the hash of the properties excluding "inputs",
    and the hash of the "inputs".
    """

    proof_elements: List[int] = []
    for key in proof_json.keys():
        if key != "inputs":
            proof_elements.extend(proof_json[key])
    return (
        message_to_bytes(proof_elements),
        message_to_bytes(proof_json["inputs"]))


def joinsplit_sign(
        signing_keypair: JoinsplitSigKeyPair,
        sender_eth_address: str,
        sender_eph_pk: EncryptionPublicKey,
        ciphertexts: List[bytes],
        proof_json: GenericProof,
) -> int:
    """
    Generate a signature on the hash of the ciphertexts, proofs and
    primary inputs. This is used to solve transaction malleability.  We chose
    to sign the hash and not the values themselves for modularity (to use the
    same code regardless of whether GROTH16 or PGHR13 proof system is chosen),
    and sign the hash of the ciphers and inputs for consistency.
    """
    assert len(ciphertexts) == constants.JS_INPUTS

    # The message to sign consists of (in order):
    #   - senders Ethereum address
    #   - senders public encryption key
    #   - ciphertexts
    #   - proof elements
    #   - public input elements
    h = sha256()
    h.update(eth_address_to_bytes(sender_eth_address))
    h.update(encode_encryption_public_key(sender_eph_pk))
    for ciphertext in ciphertexts:
        h.update(ciphertext)

    proof_bytes, pub_inputs_bytes = _encode_proof_and_inputs(proof_json)
    h.update(proof_bytes)
    h.update(pub_inputs_bytes)
    message_digest = h.digest()
    return signing.sign(signing_keypair.sk, message_digest)


def compute_h_sig(
        nf0: bytes,
        nf1: bytes,
        sign_vk: JoinsplitSigVerificationKey) -> bytes:
    """
    Compute h_sig = sha256(nf0 || nf1 || sign_vk)
    Flatten the verification key
    """
    h = sha256()
    h.update(nf0)
    h.update(nf1)
    h.update(signing.encode_vk_to_bytes(sign_vk))
    return h.digest()


def trap_r_randomness() -> str:
    """
    Compute randomness "r" as 48 random bytes
    """
    return bytes(Random.get_random_bytes(48)).hex()


def public_inputs_extract_public_values(
        public_inputs: List[str]) -> Tuple[int, int]:
    """
    Extract (v_in, v_out) from encoded public inputs. Allows client code to
    check these properties of MixParameters without needing to know the details
    of the structure / packing policy.
    """
    residual = eth_uint256_to_int(public_inputs[constants.RESIDUAL_BITS_INDEX])
    residual = residual >> constants.TOTAL_DIGEST_RESIDUAL_BITS
    v_out = (residual & constants.PUBLIC_VALUE_MASK)
    v_in = (residual >> constants.PUBLIC_VALUE_BITS) & constants.PUBLIC_VALUE_MASK
    return (v_in, v_out)


def _compute_rho_i(phi: str, hsig: bytes, i: int) -> bytes:
    """
    Returns rho_i = blake2s(0 || i || 10 || [phi]_252 || hsig)
    See: Zcash protocol spec p. 57, Section 5.4.2 Pseudo Random Functions
    """
    # [SANITY CHECK] make sure i is in the interval [0, JS_INPUTS]
    # Since we only allow for 2 input notes in the joinsplit
    assert i < constants.JS_INPUTS

    blake_hash = blake2s()

    # Append PRF^{rho} tag to a_sk
    binary_phi = hex_digest_to_binary_string(phi)
    first_252bits_phi = binary_phi[:252]
    left_leg_bin = "0" + str(i) + "10" + first_252bits_phi
    blake_hash.update(int(left_leg_bin, 2).to_bytes(32, byteorder='big'))
    blake_hash.update(hsig)
    return blake_hash.digest()


def _h_sig_randomness() -> bytes:
    """
    Compute the signature randomness "randomSeed", used for computing h_sig
    """
    return bytes(Random.get_random_bytes(32))


def _transaction_randomness() -> str:
    """
    Compute the transaction randomness "phi", used for computing the new rhoS
    """
    return bytes(Random.get_random_bytes(32)).hex()
