#!/usr/bin/env python3

# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
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
import zeth.core.proto_utils as proto_utils
from zeth.core.zksnark import IZKSnarkProvider, get_zksnark_provider, \
    ExtendedProof
from zeth.core.utils import EtherValue, digest_to_binary_string, \
    int64_to_hex, message_to_bytes, eth_address_to_bytes32, to_zeth_units, \
    get_contracts_dir, hex_list_to_uint256_list
from zeth.core.prover_client import ProverConfiguration, ProverClient
from zeth.api.zeth_messages_pb2 import ZethNote, JoinsplitInput, ProofInputs

import os
import json
from Crypto import Random
from hashlib import blake2s, sha256
import traceback
import eth_abi
from typing import Tuple, Dict, List, Iterator, Callable, Optional, Any


ZERO_UNITS_HEX = "0000000000000000"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

# JoinSplit Signature Keys definitions
JoinsplitSigVerificationKey = signing.SigningVerificationKey
JoinsplitSigSecretKey = signing.SigningSecretKey
JoinsplitSigKeyPair = signing.SigningKeyPair

ComputeHSigCB = Callable[[bytes, bytes, JoinsplitSigVerificationKey], bytes]


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


class MixParameters:
    """
    All data required to call the mixer, with no further processing required
    (except creation of a transaction). This is the result of fully processing
    a MixCallDescription, generating appropriate secret data and ZK-proof and
    signing the result.
    """
    def __init__(
            self,
            extended_proof: ExtendedProof,
            signature_vk: signing.SigningVerificationKey,
            signature: signing.Signature,
            ciphertexts: List[bytes]):
        self.extended_proof = extended_proof
        self.signature_vk = signature_vk
        self.signature = signature
        self.ciphertexts = ciphertexts

    @staticmethod
    def from_json(zksnark: IZKSnarkProvider, params_json: str) -> MixParameters:
        return MixParameters.from_json_dict(zksnark, json.loads(params_json))

    def to_json(self) -> str:
        return json.dumps(self.to_json_dict())

    def to_json_dict(self) -> Dict[str, Any]:
        ext_proof_json = self.extended_proof.to_json_dict()
        signature_vk_json = [
            str(x) for x in
            signing.verification_key_as_mix_parameter(self.signature_vk)]
        signature_json = str(signing.signature_as_mix_parameter(self.signature))
        ciphertexts_json = [x.hex() for x in self.ciphertexts]
        return {
            "extended_proof": ext_proof_json,
            "signature_vk": signature_vk_json,
            "signature": signature_json,
            "ciphertexts": ciphertexts_json,
        }

    @staticmethod
    def from_json_dict(
            zksnark: IZKSnarkProvider,
            json_dict: Dict[str, Any]) -> MixParameters:
        ext_proof = ExtendedProof.from_json_dict(
            zksnark, json_dict["extended_proof"])
        signature_pk_param = [int(x) for x in json_dict["signature_vk"]]
        signature_pk = signing.verification_key_from_mix_parameter(
            signature_pk_param)
        signature = signing.signature_from_mix_parameter(
            int(json_dict["signature"]))
        ciphertexts = [bytes.fromhex(x) for x in json_dict["ciphertexts"]]
        return MixParameters(
            ext_proof, signature_pk, signature, ciphertexts)


def mix_parameters_to_contract_arguments(
        zksnark: IZKSnarkProvider,
        pp: PairingParameters,
        mix_parameters: MixParameters) -> List[Any]:
    """
    Convert MixParameters to a list of eth ABI objects which can be passed to
    the contract's mix method.
    """
    proof_contract_params = zksnark.proof_to_contract_parameters(
        mix_parameters.extended_proof.proof, pp)
    return [
        proof_contract_params,
        signing.verification_key_as_mix_parameter(mix_parameters.signature_vk),
        signing.signature_as_mix_parameter(mix_parameters.signature),
        hex_list_to_uint256_list(mix_parameters.extended_proof.inputs),
        mix_parameters.ciphertexts,
    ]


def mix_parameters_to_dispatch_parameters(mix_parameters: MixParameters) -> bytes:
    """
    Encode parameters from mix_parameters into an array of uint256 values,
    compatible with the `dispatch` method on Mixer. This conforms to the
    `IZecaleApplication` solidity interface of Zecale
    (https://github.com/clearmatics/zecale)
    """
    vk_param = signing.verification_key_as_mix_parameter(
        mix_parameters.signature_vk)
    sigma_param = signing.signature_as_mix_parameter(mix_parameters.signature)
    return eth_abi.encode_abi(
        ['uint256[4]', 'uint256', 'bytes[]'],
        [vk_param, sigma_param, mix_parameters.ciphertexts])  # type: ignore


class MixOutputEvents:
    """
    Event data for a single joinsplit output.  Holds address (in merkle tree),
    commitment and ciphertext.
    """
    def __init__(
            self, commitment: bytes, ciphertext: bytes):
        self.commitment = commitment
        self.ciphertext = ciphertext


class MixResult:
    """
    Data structure representing the result of the mix call.
    """
    def __init__(
            self,
            new_merkle_root: bytes,
            nullifiers: List[bytes],
            output_events: List[MixOutputEvents]):
        self.new_merkle_root = new_merkle_root
        self.nullifiers = nullifiers
        self.output_events = output_events


def event_args_to_mix_result(event_args: Any) -> MixResult:
    mix_out_args = zip(event_args.commitments, event_args.ciphertexts)
    out_events = [MixOutputEvents(c, ciph) for (c, ciph) in mix_out_args]
    return MixResult(
        new_merkle_root=event_args.root,
        nullifiers=event_args.nullifiers,
        output_events=out_events)


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


def get_dummy_input_and_address(
        a_pk: OwnershipPublicKey) -> Tuple[int, ZethNote]:
    """
    Create a zeth note and address, for use as circuit inputs where there is no
    real input.
    """
    dummy_note = ZethNote(
        apk=ownership_key_as_hex(a_pk),
        value=ZERO_UNITS_HEX,
        rho=_get_dummy_rho(),
        trap_r=_trap_r_randomness())
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
            prover_config: ProverConfiguration,
            mixer_instance: Any):
        self.web3 = web3
        self.prover_config = prover_config
        self.mixer_instance = mixer_instance

    @staticmethod
    def deploy(
            web3: Any,
            prover_client: ProverClient,
            deployer_eth_address: str,
            deployer_eth_private_key: Optional[bytes],
            token_address: Optional[str] = None,
            permitted_dispatcher: Optional[str] = None,
            vk_hash: Optional[str] = None,
            deploy_gas: Optional[int] = None
    ) -> Tuple[MixerClient, contracts.InstanceDescription]:
        """
        Deploy Zeth contracts.
        """
        prover_config = prover_client.get_configuration()
        vk = prover_client.get_verification_key()
        deploy_gas = deploy_gas or constants.DEPLOYMENT_GAS_WEI

        contracts_dir = get_contracts_dir()
        zksnark = get_zksnark_provider(prover_config.zksnark_name)
        pp = prover_config.pairing_parameters
        mixer_name = zksnark.get_contract_name(pp)
        mixer_src = os.path.join(contracts_dir, mixer_name + ".sol")

        # Constructor parameters have the form:
        #   uint256 mk_depth
        #   address token
        #   ... snark-specific key data ...
        constructor_parameters: List[Any] = [
            constants.ZETH_MERKLE_TREE_DEPTH,  # mk_depth
            token_address or ZERO_ADDRESS,     # token
            zksnark.verification_key_to_contract_parameters(vk, pp),  # vk
            permitted_dispatcher or ZERO_ADDRESS,  # permitted_dispatcher
            int(vk_hash, 16) if vk_hash else 0,  # vk_hash
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
        client = MixerClient(web3, prover_config, mixer_instance)
        return client, mixer_description

    def deposit(
            self,
            prover_client: ProverClient,
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
            prover_client,
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
            prover_client: ProverClient,
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
        """
        Create and broadcast a transactions that calls the mixer with the given
        parameters. Requires a ProverClient for proof generation.
        """
        mix_params, _ = self.create_mix_parameters_and_signing_key(
            prover_client,
            mk_tree,
            sender_ownership_keypair,
            sender_eth_address,
            inputs,
            outputs,
            v_in,
            v_out,
            compute_h_sig_cb)
        return self.mix(
            mix_params,
            sender_eth_address,
            sender_eth_private_key,
            tx_value or v_in,
            constants.DEFAULT_MIX_GAS_WEI)

    def mix(
            self,
            mix_params: MixParameters,
            sender_eth_address: str,
            sender_eth_private_key: Optional[bytes],
            tx_value: EtherValue,
            call_gas: int = constants.DEFAULT_MIX_GAS_WEI) -> str:
        """
        Given a MixParameters object, create and broadcast a transaction
        performing the appropriate mix call.
        """
        mixer_call = self._create_mix_call(mix_params)
        tx_hash = contracts.send_contract_call(
            self.web3,
            mixer_call,
            sender_eth_address,
            sender_eth_private_key,
            tx_value,
            call_gas)
        return tx_hash.hex()

    def mix_call(
            self,
            mix_params: MixParameters,
            sender_eth_address: str,
            tx_value: EtherValue,
            call_gas: int = constants.DEFAULT_MIX_GAS_WEI) -> bool:
        """
        Call the mix method (executes on the RPC host without creating a
        transaction). Returns True if the call succeeds. False, otherwise.
        """
        mixer_call = self._create_mix_call(mix_params)
        try:
            contracts.local_contract_call(
                mixer_call,
                sender_eth_address,
                tx_value,
                call_gas)
            return True

        except ValueError:
            print("error executing mix call:")
            traceback.print_exc()

        return False

    def _create_mix_call(
            self,
            mix_parameters: MixParameters) -> Any:
        """
        Given a MixParameters object and other transaction properties, create a
        web3 call object, which can be used to create a transaction or a query.
        """
        zksnark = get_zksnark_provider(self.prover_config.zksnark_name)
        pp = self.prover_config.pairing_parameters
        mix_params_eth = mix_parameters_to_contract_arguments(
            zksnark, pp, mix_parameters)
        return self.mixer_instance.functions.mix(*mix_params_eth)

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
        output_note0, output_note1 = _create_zeth_notes(
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
            sender_eth_address: str,
            for_dispatch_call: bool = False
    ) -> MixParameters:
        """
        Create the MixParameters from MixCallDescription, signing keypair, sender
        address and derived data (prover inputs and proof). This includes
        creating and encrypting the plaintext messages, and generating the
        one-time signature.

        If for_dispatch_call is set, the parameters are to be passed to the
        Mixer's `dispatch` call in a later operation (in which proof data is
        not available), hence proof is ommitted from the signature.
        """

        # Encrypt the notes
        outputs_and_notes = zip(mix_call_desc.outputs, prover_inputs.js_outputs) \
            # pylint: disable=no-member
        output_notes_with_k_pk: List[Tuple[ZethNote, EncryptionPublicKey]] = \
            [(note, zeth_addr.k_pk)
             for ((zeth_addr, _), note) in outputs_and_notes]
        ciphertexts = encrypt_notes(output_notes_with_k_pk)

        # Sign
        zksnark = get_zksnark_provider(self.prover_config.zksnark_name)
        signature = joinsplit_sign(
            zksnark,
            self.prover_config.pairing_parameters,
            signing_keypair,
            sender_eth_address,
            ciphertexts,
            ext_proof,
            for_dispatch_call)

        mix_params = MixParameters(
            ext_proof, signing_keypair.vk, signature, ciphertexts)
        return mix_params

    def create_mix_parameters_and_signing_key(
            self,
            prover_client: ProverClient,
            mk_tree: MerkleTree,
            sender_ownership_keypair: OwnershipKeyPair,
            sender_eth_address: str,
            inputs: List[Tuple[int, ZethNote]],
            outputs: List[Tuple[ZethAddressPub, EtherValue]],
            v_in: EtherValue,
            v_out: EtherValue,
            compute_h_sig_cb: Optional[ComputeHSigCB] = None,
            for_dispatch_call: bool = False
    ) -> Tuple[MixParameters, JoinsplitSigKeyPair]:
        """
        Convenience function around creation of MixCallDescription, ProofInputs,
        Proof and MixParameters. If for_dispatch_call is set, the parameters
        are to be passed to the Mixer's `dispatch` call in a later operation
        (in which proof data is not available), hence proof is ommitted from
        the signature.
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
        ext_proof = prover_client.get_proof(prover_inputs)

        # Create the final MixParameters object
        mix_params = self.create_mix_parameters_from_proof(
            mix_call_desc,
            prover_inputs,
            signing_keypair,
            ext_proof,
            sender_eth_address,
            for_dispatch_call)

        return mix_params, signing_keypair


def encrypt_notes(
        notes: List[Tuple[ZethNote, EncryptionPublicKey]]) -> List[bytes]:
    """
    Encrypts a set of output notes to be decrypted by the respective receivers.
    Returns the ciphertexts corresponding to each note.
    """

    def _encrypt_note(out_note: ZethNote, pub_key: EncryptionPublicKey) -> bytes:
        out_note_bytes = proto_utils.zeth_note_to_bytes(out_note)

        return encrypt(out_note_bytes, pub_key)

    ciphertexts = [_encrypt_note(note, pk) for (note, pk) in notes]
    return ciphertexts


def receive_note(
        out_ev: MixOutputEvents,
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
            proto_utils.zeth_note_from_bytes(plaintext))
    except InvalidSignature:
        return None
    except ValueError:
        return None


def parse_mix_call(
        mixer_instance: Any,
        _tx_receipt: str) -> MixResult:
    """
    Get the logs data associated with this mixing
    """
    log_mix_filter = mixer_instance.eventFilter("LogMix", {'fromBlock': 'latest'})
    log_mix_events = log_mix_filter.get_all_entries()
    mix_results = [event_args_to_mix_result(ev.args) for ev in log_mix_events]
    return mix_results[0]


def get_mix_results(
        web3: Any,
        mixer_instance: Any,
        start_block: int,
        end_block: int,
        batch_size: Optional[int] = None) -> Iterator[MixResult]:
    """
    Iterator for all events generated by 'mix' executions, over some block
    range (inclusive of `end_block`). Batch eth RPC calls to avoid too many
    calls, and holding huge lists of events in memory.
    """
    logs = contracts.get_event_logs(
        web3, mixer_instance, "LogMix", start_block, end_block, batch_size)
    for event_data in logs:
        yield event_args_to_mix_result(event_data.args)


def joinsplit_sign(
        zksnark: IZKSnarkProvider,
        pp: PairingParameters,
        signing_keypair: JoinsplitSigKeyPair,
        sender_eth_address: str,
        ciphertexts: List[bytes],
        extproof: ExtendedProof,
        for_dispatch_call: bool = False) -> int:
    """
    Generate a signature on the hash of the ciphertexts, proofs and primary
    inputs. This is used to solve transaction malleability. We chose to sign
    the hash and not the values themselves for modularity (to use the same code
    regardless of whether GROTH16 or PGHR13 proof system is chosen), and sign
    the hash of the ciphers and inputs for consistency. If for_dispatch_call is
    set, the parameters are to be passed to the Mixer's `dispatch` call in a
    later operation (in which proof data is not available), hence proof is
    ommitted from the signature.
    """
    assert len(ciphertexts) == constants.JS_INPUTS

    # The message to sign consists of (in order):
    #   - senders Ethereum address
    #   - ciphertexts
    #   - proof elements (if for_dispatch_call is False)
    #   - public input elements
    h = sha256()
    h.update(eth_address_to_bytes32(sender_eth_address))
    for ciphertext in ciphertexts:
        h.update(ciphertext)

    proof_bytes, pub_inputs_bytes = _proof_and_inputs_to_bytes(
        zksnark, pp, extproof)

    # If for_dispatch_call is set, omit proof from the signature. See
    # MixerBase.sol.
    if not for_dispatch_call:
        h.update(proof_bytes)

    h.update(pub_inputs_bytes)
    message_digest = h.digest()
    return signing.sign(signing_keypair.sk, message_digest)


def compute_commitment(zeth_note: ZethNote, pp: PairingParameters) -> bytes:
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

    cm_field = int.from_bytes(cm, byteorder="big") % pp.scalar_field_mod()
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
    h.update(sign_vk.to_bytes())
    return h.digest()


def _create_zeth_notes(
        phi: bytes,
        hsig: bytes,
        output0: Tuple[OwnershipPublicKey, int],
        output1: Tuple[OwnershipPublicKey, int]
) -> Tuple[ZethNote, ZethNote]:
    """
    Create two ordered ZethNotes. Used to generate new output
    notes to be passed to the prover server.
    """
    (recipient0, value0) = output0
    (recipient1, value1) = output1

    rho0 = _compute_rho_i(phi, hsig, 0)
    trap_r0 = _trap_r_randomness()
    note0 = ZethNote(
        apk=ownership_key_as_hex(recipient0),
        value=int64_to_hex(value0),
        rho=rho0.hex(),
        trap_r=trap_r0)

    rho1 = _compute_rho_i(phi, hsig, 1)
    trap_r1 = _trap_r_randomness()
    note1 = ZethNote(
        apk=ownership_key_as_hex(recipient1),
        value=int64_to_hex(value1),
        rho=rho1.hex(),
        trap_r=trap_r1)

    return note0, note1


def _proof_and_inputs_to_bytes(
        snark: IZKSnarkProvider,
        pp: PairingParameters,
        extproof: ExtendedProof) -> Tuple[bytes, bytes]:
    """
    Given a proof object, compute the byte encodings of the properties
    excluding "inputs", and the byte encoding of the "inputs". These are used
    when hashing the mixer call parameters for signing, so must match what
    happens in the mixer contract.
    """
    # TODO: avoid duplicating this encoding to evm parameters
    proof = extproof.proof
    return \
        message_to_bytes(snark.proof_to_contract_parameters(proof, pp)), \
        message_to_bytes(hex_list_to_uint256_list(extproof.inputs))


def _trap_r_randomness() -> str:
    """
    Compute randomness `r`
    """
    assert (constants.TRAPR_LENGTH_BYTES << 3) == constants.TRAPR_LENGTH
    return bytes(Random.get_random_bytes(constants.TRAPR_LENGTH_BYTES)).hex()


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


def _get_dummy_rho() -> str:
    assert (constants.RHO_LENGTH_BYTES << 3) == constants.RHO_LENGTH
    return bytes(Random.get_random_bytes(constants.RHO_LENGTH_BYTES)).hex()


def _phi_randomness() -> bytes:
    """
    Compute the transaction randomness "phi", used for computing the new rhoS
    """
    return bytes(Random.get_random_bytes(constants.PHI_LENGTH_BYTES))
