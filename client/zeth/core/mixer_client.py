#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
import zeth.core.contracts as contracts
import zeth.core.constants as constants
from zeth.core.zeth_address import ZethAddressPub, ZethAddress
from zeth.core.ownership import OwnershipPublicKey, OwnershipSecretKey, \
    OwnershipKeyPair, ownership_key_as_hex
from zeth.core.encryption import \
    EncryptionPublicKey, EncryptionSecretKey, InvalidSignature, \
    generate_encryption_keypair, encrypt, decrypt
from zeth.core.merkle_tree import MerkleTree, compute_merkle_path
from zeth.core.pairing import PairingParameters
import zeth.core.signing as signing
from zeth.core.zksnark import IZKSnarkProvider, get_zksnark_provider, \
    ExtendedProof, IVerificationKey
from zeth.core.utils import EtherValue, digest_to_binary_string, \
    int64_to_hex, message_to_bytes, eth_address_to_bytes32, eth_uint256_to_int, \
    to_zeth_units, get_contracts_dir, hex_list_to_uint256_list
from zeth.core.prover_client import ProverClient
from zeth.api.zeth_messages_pb2 import ZethNote, JoinsplitInput, ProofInputs

import os
import json
from Crypto import Random
from hashlib import blake2s, sha256
from typing import Tuple, Dict, List, Callable, Optional, Any


ZERO_UNITS_HEX = "0000000000000000"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

# ZethNote binary serialization format:
#   [apk   : APK_LENGTH_BYTES]
#   [value : PUBLIC_VALUE_LENGTH_BYTES]
#   [rho   : RHO_LENGTH_BYTES]
#   [trapr : TRAPR_LENGTH_BYTES]
_APK_OFFSET_BYTES = 0
_VALUE_OFFSET_BYTES = _APK_OFFSET_BYTES + constants.APK_LENGTH_BYTES
_RHO_OFFSET_BYTES = _VALUE_OFFSET_BYTES + constants.PUBLIC_VALUE_LENGTH_BYTES
_TRAPR_OFFSET_BYTES = _RHO_OFFSET_BYTES + constants.RHO_LENGTH_BYTES
assert _TRAPR_OFFSET_BYTES + constants.TRAPR_LENGTH_BYTES \
    == constants.NOTE_LENGTH_BYTES

# JoinSplit Signature Keys definitions
JoinsplitSigVerificationKey = signing.SigningVerificationKey
JoinsplitSigSecretKey = signing.SigningSecretKey
JoinsplitSigKeyPair = signing.SigningKeyPair


ComputeHSigCB = Callable[[bytes, bytes, JoinsplitSigVerificationKey], bytes]


class JoinsplitInputNote:
    """
    A ZethNote, along with the nullifier and location in Merkle tree.
    """

    def __init__(self, note: ZethNote, nullifier: str, merkle_location: int):
        self.note = note
        self.nullifier = nullifier
        self.merkle_location = merkle_location


class MixCallDescription:
    """
    High-level description of a call to the mixer contract. Holds information
    used when generating the ProofInputs, ZK-proof and final MixParameters
    object.
    """
    def __init__(
            self,
            mk_tree: MerkleTree,
            sender_ownership_keypair: OwnershipKeyPair,
            inputs: List[Tuple[int, ZethNote]],
            outputs: List[Tuple[ZethAddressPub, EtherValue]],
            v_in: EtherValue,
            v_out: EtherValue,
            compute_h_sig_cb: Optional[ComputeHSigCB] = None):
        assert len(inputs) <= constants.JS_INPUTS
        assert len(outputs) <= constants.JS_OUTPUTS

        self.mk_tree = mk_tree
        self.sender_ownership_keypair = sender_ownership_keypair
        self.v_in = v_in
        self.v_out = v_out
        self.compute_h_sig_cb = compute_h_sig_cb

        # Perform some cleaning and minimal pre-processing of the data. Compute
        # and store data that is not derivable from the ProverInput or Proof
        # structs (such as the encryption keys for receivers), making it
        # available to MixerClient calls.

        # Expand inputs with dummy entries and compute merkle paths.
        sender_a_pk = sender_ownership_keypair.a_pk
        self.inputs = \
            inputs + \
            [get_dummy_input_and_address(sender_a_pk)
             for _ in range(constants.JS_INPUTS - len(inputs))]

        # Pad the list of outputs if necessary
        if len(outputs) < constants.JS_OUTPUTS:
            dummy_k_pk = generate_encryption_keypair().k_pk
            dummy_addr_pk = ZethAddressPub(sender_a_pk, dummy_k_pk)
            self.outputs = \
                outputs + \
                [(dummy_addr_pk, EtherValue(0))
                 for _ in range(constants.JS_OUTPUTS - len(outputs))]
        else:
            self.outputs = outputs


def create_zeth_notes(
        phi: bytes,
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


def zeth_note_to_bytes(zeth_note_grpc_obj: ZethNote) -> bytes:
    apk_bytes = bytes.fromhex(zeth_note_grpc_obj.apk)
    value_bytes = bytes.fromhex(zeth_note_grpc_obj.value)
    rho_bytes = bytes.fromhex(zeth_note_grpc_obj.rho)
    trap_r_bytes = bytes.fromhex(zeth_note_grpc_obj.trap_r)
    note_bytes = apk_bytes + value_bytes + rho_bytes + trap_r_bytes
    assert len(note_bytes) == (constants.NOTE_LENGTH_BYTES)
    return note_bytes


def zeth_note_from_bytes(note_bytes: bytes) -> ZethNote:
    if len(note_bytes) != (constants.NOTE_LENGTH_BYTES):
        raise ValueError(
            f"note_bytes len {len(note_bytes)}, "
            f"(expected {constants.NOTE_LENGTH_BYTES})")
    apk = note_bytes[
        _APK_OFFSET_BYTES:_APK_OFFSET_BYTES + constants.APK_LENGTH_BYTES]
    value = note_bytes[
        _VALUE_OFFSET_BYTES:
        _VALUE_OFFSET_BYTES + constants.PUBLIC_VALUE_LENGTH_BYTES]
    rho = note_bytes[
        _RHO_OFFSET_BYTES:_RHO_OFFSET_BYTES + constants.RHO_LENGTH_BYTES]
    trap_r = note_bytes[_TRAPR_OFFSET_BYTES:]
    return ZethNote(
        apk=apk.hex(), value=value.hex(), rho=rho.hex(), trap_r=trap_r.hex())


def compute_commitment(zeth_note: ZethNote) -> bytes:
    """
    Used by the recipient of a payment to recompute the commitment and check
    the membership in the tree to confirm the validity of a payment
    """
    # inner_k = blake2s(r || a_pk || rho || v)
    blake = blake2s()
    blake.update(bytes.fromhex(zeth_note.trap_r))
    blake.update(bytes.fromhex(zeth_note.apk))
    blake.update(bytes.fromhex(zeth_note.rho))
    blake.update(bytes.fromhex(zeth_note.value))
    cm = blake.digest()

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


def write_verification_key(vk: IVerificationKey, filename: str) -> None:
    """
    Writes the verification key (object) in a json file
    """
    with open(filename, 'w') as outfile:
        json.dump(vk.to_json_dict(), outfile)


def get_dummy_rho() -> str:
    assert (constants.RHO_LENGTH_BYTES << 3) == constants.RHO_LENGTH
    return bytes(Random.get_random_bytes(constants.RHO_LENGTH_BYTES)).hex()


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
    def deploy(
            web3: Any,
            prover_client: ProverClient,
            deployer_eth_address: str,
            deployer_eth_private_key: Optional[bytes],
            token_address: Optional[str] = None,
            deploy_gas: Optional[int] = None,
            zksnark: Optional[IZKSnarkProvider] = None) \
            -> Tuple[MixerClient, contracts.InstanceDescription]:
        """
        Deploy Zeth contracts.
        """
        zksnark = zksnark or get_zksnark_provider(constants.ZKSNARK_DEFAULT)
        prover_config = prover_client.get_configuration()
        vk_proto = prover_client.get_verification_key()
        pp = prover_config.pairing_parameters
        vk = zksnark.verification_key_from_proto(vk_proto)
        deploy_gas = deploy_gas or constants.DEPLOYMENT_GAS_WEI

        print("[INFO] writing verification key...")
        write_verification_key(vk, "vk.json")

        contracts_dir = get_contracts_dir()
        mixer_name = zksnark.get_contract_name()
        mixer_src = os.path.join(contracts_dir, mixer_name + ".sol")

        # Constructor parameters have the form:
        #   uint256 mk_depth
        #   address token
        #   ... snark-specific key data ...
        constructor_parameters: List[Any] = [
            constants.ZETH_MERKLE_TREE_DEPTH,  # mk_depth
            token_address or ZERO_ADDRESS,     # token
            zksnark.verification_key_to_contract_parameters(vk, pp),  # vk
        ]
        mixer_description = contracts.InstanceDescription.deploy(
            web3,
            mixer_src,
            mixer_name,
            deployer_eth_address,
            deployer_eth_private_key,
            deploy_gas,
            compiler_flags={},
            args=constructor_parameters)
        mixer_instance = mixer_description.instantiate(web3)
        client = MixerClient(web3, prover_client, mixer_instance, zksnark)
        return client, mixer_description

    def deposit(
            self,
            mk_tree: MerkleTree,
            zeth_address: ZethAddress,
            sender_eth_address: str,
            sender_eth_private_key: Optional[bytes],
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
            sender_eth_private_key=sender_eth_private_key,
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
            sender_eth_private_key: Optional[bytes],
            inputs: List[Tuple[int, ZethNote]],
            outputs: List[Tuple[ZethAddressPub, EtherValue]],
            v_in: EtherValue,
            v_out: EtherValue,
            tx_value: Optional[EtherValue] = None,
            compute_h_sig_cb: Optional[ComputeHSigCB] = None) -> str:
        mix_params, _ = self.create_mix_parameters_and_signing_key(
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
        pp = self._prover_client.get_configuration().pairing_parameters
        return contracts.mix(
            self.web3,
            self._zksnark,
            pp,
            self.mixer_instance,
            mix_params,
            sender_eth_address,
            sender_eth_private_key,
            tx_value,
            constants.DEFAULT_MIX_GAS_WEI)

    @staticmethod
    def create_prover_inputs(
            mix_call_desc: MixCallDescription
    ) -> Tuple[ProofInputs, signing.SigningKeyPair]:
        """
        Given the basic parameters for a mix call, compute the input to the prover
        server, and the signing key pair.
        """

        # Compute Merkle paths
        mk_tree = mix_call_desc.mk_tree
        mk_root = mk_tree.get_root()
        inputs = mix_call_desc.inputs
        mk_paths = [compute_merkle_path(addr, mk_tree) for addr, _ in inputs]

        # Extract (<ownership-address>, <value>) tuples
        outputs_with_a_pk = \
            [(zeth_addr.a_pk, to_zeth_units(value))
             for (zeth_addr, value) in mix_call_desc.outputs]
        output0 = outputs_with_a_pk[0]
        output1 = outputs_with_a_pk[1]

        # Public input and output values as Zeth units
        public_in_value_zeth_units = to_zeth_units(mix_call_desc.v_in)
        public_out_value_zeth_units = to_zeth_units(mix_call_desc.v_out)

        # Generate the signing key
        signing_keypair = signing.gen_signing_keypair()
        sender_ask = mix_call_desc.sender_ownership_keypair.a_sk

        # Compute the input note nullifiers
        (input_address0, input_note0) = mix_call_desc.inputs[0]
        (input_address1, input_note1) = mix_call_desc.inputs[1]
        input_nullifier0 = compute_nullifier(input_note0, sender_ask)
        input_nullifier1 = compute_nullifier(input_note1, sender_ask)

        # Convert to JoinsplitInput objects
        js_inputs: List[JoinsplitInput] = [
            create_joinsplit_input(
                mk_paths[0],
                input_address0,
                input_note0,
                sender_ask,
                input_nullifier0),
            create_joinsplit_input(
                mk_paths[1],
                input_address1,
                input_note1,
                sender_ask,
                input_nullifier1)
        ]

        # Use the specified or default h_sig computation
        compute_h_sig_cb = mix_call_desc.compute_h_sig_cb or compute_h_sig
        h_sig = compute_h_sig_cb(
            input_nullifier0,
            input_nullifier1,
            signing_keypair.vk)
        phi = _phi_randomness()

        # Joinsplit Output Notes
        output_note0, output_note1 = create_zeth_notes(
            phi, h_sig, output0, output1)
        js_outputs = [
            output_note0,
            output_note1
        ]

        proof_inputs = ProofInputs(
            mk_root=mk_root.hex(),
            js_inputs=js_inputs,
            js_outputs=js_outputs,
            pub_in_value=int64_to_hex(public_in_value_zeth_units),
            pub_out_value=int64_to_hex(public_out_value_zeth_units),
            h_sig=h_sig.hex(),
            phi=phi.hex())
        return (proof_inputs, signing_keypair)

    def create_mix_parameters_from_proof(
            self,
            mix_call_desc: MixCallDescription,
            prover_inputs: ProofInputs,
            signing_keypair: signing.SigningKeyPair,
            ext_proof: ExtendedProof,
            sender_eth_address: str
    ) -> contracts.MixParameters:

        # Encrypt the notes
        outputs_and_notes = zip(mix_call_desc.outputs, prover_inputs.js_outputs) \
            # pylint: disable=no-member
        output_notes_with_k_pk: List[Tuple[ZethNote, EncryptionPublicKey]] = \
            [(note, zeth_addr.k_pk)
             for ((zeth_addr, _), note) in outputs_and_notes]
        ciphertexts = encrypt_notes(output_notes_with_k_pk)

        # Sign
        pp = self._prover_client.get_configuration().pairing_parameters
        signature = joinsplit_sign(
            self._zksnark,
            pp,
            signing_keypair,
            sender_eth_address,
            ciphertexts,
            ext_proof)

        mix_params = contracts.MixParameters(
            ext_proof,
            signing_keypair.vk,
            signature,
            ciphertexts)
        return mix_params

    def create_mix_parameters_and_signing_key(
            self,
            mk_tree: MerkleTree,
            sender_ownership_keypair: OwnershipKeyPair,
            sender_eth_address: str,
            inputs: List[Tuple[int, ZethNote]],
            outputs: List[Tuple[ZethAddressPub, EtherValue]],
            v_in: EtherValue,
            v_out: EtherValue,
            compute_h_sig_cb: Optional[ComputeHSigCB] = None
    ) -> Tuple[contracts.MixParameters, JoinsplitSigKeyPair]:
        """
        Convenient around creation of MixCallDescription, ProofInputs, Proof and
        MixParameters.
        """
        # Generate prover inputs and signing key
        mix_call_desc = MixCallDescription(
            mk_tree,
            sender_ownership_keypair,
            inputs,
            outputs,
            v_in,
            v_out,
            compute_h_sig_cb)
        prover_inputs, signing_keypair = MixerClient.create_prover_inputs(
            mix_call_desc)

        # Query the prover_server for the related proof
        ext_proof_proto = self._prover_client.get_proof(prover_inputs)
        ext_proof = self._zksnark.extended_proof_from_proto(ext_proof_proto)

        # Create the final MixParameters object
        mix_params = self.create_mix_parameters_from_proof(
            mix_call_desc,
            prover_inputs,
            signing_keypair,
            ext_proof,
            sender_eth_address)

        return mix_params, signing_keypair

    def mix(
            self,
            mix_params: contracts.MixParameters,
            sender_eth_address: str,
            sender_eth_private_key: Optional[bytes],
            tx_value: Optional[EtherValue] = None,
            call_gas: int = constants.DEFAULT_MIX_GAS_WEI) -> str:
        pp = self._prover_client.get_configuration().pairing_parameters
        return contracts.mix(
            self.web3,
            self._zksnark,
            pp,
            self.mixer_instance,
            mix_params,
            sender_eth_address,
            sender_eth_private_key,
            tx_value,
            call_gas)

    def mix_call(
            self,
            mix_params: contracts.MixParameters,
            sender_eth_address: str,
            wei_pub_value: int,
            call_gas: int) -> bool:
        pp = self._prover_client.get_configuration().pairing_parameters
        return contracts.mix_call(
            self._zksnark,
            pp,
            self.mixer_instance,
            mix_params,
            sender_eth_address,
            wei_pub_value,
            call_gas)


def encrypt_notes(
        notes: List[Tuple[ZethNote, EncryptionPublicKey]]
) -> List[bytes]:
    """
    Encrypts a set of output notes to be decrypted by the respective receivers.
    Returns the ciphertexts corresponding to each note.
    """

    def _encrypt_note(out_note: ZethNote, pub_key: EncryptionPublicKey) -> bytes:
        out_note_bytes = zeth_note_to_bytes(out_note)

        return encrypt(out_note_bytes, pub_key)

    ciphertexts = [_encrypt_note(note, pk) for (note, pk) in notes]
    return ciphertexts


def receive_note(
        out_ev: contracts.MixOutputEvents,
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
        plaintext = decrypt(out_ev.ciphertext, receiver_k_sk)
        return (
            out_ev.commitment,
            zeth_note_from_bytes(plaintext))
    except InvalidSignature:
        return None
    except ValueError:
        return None


def _proof_and_inputs_to_bytes(
        snark: IZKSnarkProvider,
        pp: PairingParameters,
        extproof: ExtendedProof) -> Tuple[bytes, bytes]:
    """
    Given a proof object, compute the hash of the properties excluding "inputs",
    and the hash of the "inputs".
    """
    # TODO: avoid duplicating this encoding to evm parameters
    proof = extproof.proof
    return \
        message_to_bytes(snark.proof_to_contract_parameters(proof, pp)), \
        message_to_bytes(hex_list_to_uint256_list(extproof.inputs))


def joinsplit_sign(
        zksnark: IZKSnarkProvider,
        pp: PairingParameters,
        signing_keypair: JoinsplitSigKeyPair,
        sender_eth_address: str,
        ciphertexts: List[bytes],
        extproof: ExtendedProof) -> int:
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
    #   - ciphertexts
    #   - proof elements
    #   - public input elements
    h = sha256()
    h.update(eth_address_to_bytes32(sender_eth_address))
    for ciphertext in ciphertexts:
        h.update(ciphertext)

    proof_bytes, pub_inputs_bytes = _proof_and_inputs_to_bytes(
        zksnark, pp, extproof)
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
    Compute randomness `r`
    """
    assert (constants.TRAPR_LENGTH_BYTES << 3) == constants.TRAPR_LENGTH
    return bytes(Random.get_random_bytes(constants.TRAPR_LENGTH_BYTES)).hex()


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
    v_in = \
        (residual >> constants.PUBLIC_VALUE_LENGTH) & constants.PUBLIC_VALUE_MASK
    return (v_in, v_out)


def _compute_rho_i(phi: bytes, hsig: bytes, i: int) -> bytes:
    """
    Returns rho_i = blake2s(0 || i || 10 || [phi]_252 || hsig)
    See: Zcash protocol spec p. 57, Section 5.4.2 Pseudo Random Functions
    """
    # [SANITY CHECK] make sure i is in the interval [0, JS_INPUTS]. For now,
    # this code also relies on JS_INPUTS being <= 2.
    assert i < constants.JS_INPUTS
    assert constants.JS_INPUTS <= 2, \
        "function needs updating to support JS_INPUTS > 2"

    blake_hash = blake2s()

    # Append PRF^{rho} tag to a_sk
    binary_phi = digest_to_binary_string(phi)
    first_252bits_phi = binary_phi[:252]
    left_leg_bin = "0" + str(i) + "10" + first_252bits_phi
    blake_hash.update(int(left_leg_bin, 2).to_bytes(32, byteorder='big'))
    blake_hash.update(hsig)
    return blake_hash.digest()


def _phi_randomness() -> bytes:
    """
    Compute the transaction randomness "phi", used for computing the new rhoS
    """
    return bytes(Random.get_random_bytes(constants.PHI_LENGTH_BYTES))
