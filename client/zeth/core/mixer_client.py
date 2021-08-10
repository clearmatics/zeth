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
    get_contracts_dir, hex_to_uint256_list
from zeth.core.prover_client import ProverConfiguration, ProverClient
import zeth.api.zeth_messages_pb2 as api

import os
import json
import math
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

ComputeHSigCB = Callable[[List[bytes], JoinsplitSigVerificationKey], bytes]


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
            inputs: List[Tuple[int, api.ZethNote]],
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
            public_data: List[int],
            signature_vk: signing.SigningVerificationKey,
            signature: signing.Signature,
            ciphertexts: List[bytes]):
        self.extended_proof = extended_proof
        self.public_data = public_data
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
        public_data = [hex(x) for x in self.public_data]
        signature_vk_json = [
            str(x) for x in
            signing.verification_key_as_mix_parameter(self.signature_vk)]
        signature_json = str(signing.signature_as_mix_parameter(self.signature))
        ciphertexts_json = [x.hex() for x in self.ciphertexts]
        return {
            "extended_proof": ext_proof_json,
            "public_data": public_data,
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
        public_data = [int(x, 16) for x in json_dict["public_data"]]
        signature_pk_param = [int(x) for x in json_dict["signature_vk"]]
        signature_pk = signing.verification_key_from_mix_parameter(
            signature_pk_param)
        signature = signing.signature_from_mix_parameter(
            int(json_dict["signature"]))
        ciphertexts = [bytes.fromhex(x) for x in json_dict["ciphertexts"]]
        return MixParameters(
            ext_proof, public_data, signature_pk, signature, ciphertexts)


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
        mix_parameters.public_data,
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
    public_data = mix_parameters.public_data
    ciphertexts = mix_parameters.ciphertexts
    return eth_abi.encode_abi(
        ['uint256[4]', 'uint256', 'uint256[]', 'bytes[]'],
        [vk_param, sigma_param, public_data, ciphertexts])  # type: ignore


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


def create_api_joinsplit_input(
        merkle_path: List[str],
        address: int,
        note: api.ZethNote,
        a_sk: OwnershipSecretKey,
        nullifier: bytes) -> api.JoinsplitInput:
    return api.JoinsplitInput(
        merkle_path=merkle_path,
        address=address,
        note=note,
        spending_ask=ownership_key_as_hex(a_sk),
        nullifier=nullifier.hex())


def get_dummy_input_and_address(
        a_pk: OwnershipPublicKey) -> Tuple[int, api.ZethNote]:
    """
    Create a zeth note and address, for use as circuit inputs where there is no
    real input.
    """
    dummy_note = api.ZethNote(
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
        vk_hash_evm = list(hex_to_uint256_list(vk_hash)) if vk_hash else [0, 0]
        assert len(vk_hash_evm) == 2

        # Constructor parameters have the form:
        #   uint256 mk_depth
        #   address token
        #   ... snark-specific key data ...
        constructor_parameters: List[Any] = [
            constants.ZETH_MERKLE_TREE_DEPTH,  # mk_depth
            token_address or ZERO_ADDRESS,     # token
            zksnark.verification_key_to_contract_parameters(vk, pp),  # vk
            permitted_dispatcher or ZERO_ADDRESS,  # permitted_dispatcher
            vk_hash_evm  # vk_hash
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
            inputs: List[Tuple[int, api.ZethNote]],
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
    ) -> Tuple[api.ProofInputs, signing.SigningKeyPair]:
        """
        Given the basic parameters for a mix call, compute the input to the prover
        server, and the signing key pair.
        """

        # Compute Merkle paths
        mk_tree = mix_call_desc.mk_tree
        sender_ask = mix_call_desc.sender_ownership_keypair.a_sk

        def _create_api_input(
                input_address: int,
                input_note: api.ZethNote) -> api.JoinsplitInput:
            mk_path = compute_merkle_path(input_address, mk_tree)
            input_nullifier = compute_nullifier(input_note, sender_ask)
            return create_api_joinsplit_input(
                mk_path,
                input_address,
                input_note,
                sender_ask,
                input_nullifier)

        inputs = mix_call_desc.inputs
        api_inputs = [_create_api_input(addr, note) for addr, note in inputs]

        mk_root = mk_tree.get_root()

        # Extract (<ownership-address>, <value>) tuples
        outputs_with_a_pk = \
            [(zeth_addr.a_pk, to_zeth_units(value))
             for (zeth_addr, value) in mix_call_desc.outputs]

        # Public input and output values as Zeth units
        public_in_value_zeth_units = to_zeth_units(mix_call_desc.v_in)
        public_out_value_zeth_units = to_zeth_units(mix_call_desc.v_out)

        # Generate the signing key
        signing_keypair = signing.gen_signing_keypair()

        # Use the specified or default h_sig computation
        compute_h_sig_cb = mix_call_desc.compute_h_sig_cb or compute_h_sig
        h_sig = compute_h_sig_cb(
            [bytes.fromhex(input.nullifier) for input in api_inputs],
            signing_keypair.vk)
        phi = _phi_randomness()

        # Create the api.ZethNote objects
        api_outputs = _create_api_zeth_notes(phi, h_sig, outputs_with_a_pk)

        proof_inputs = api.ProofInputs(
            mk_root=mk_root.hex(),
            js_inputs=api_inputs,
            js_outputs=api_outputs,
            pub_in_value=int64_to_hex(public_in_value_zeth_units),
            pub_out_value=int64_to_hex(public_out_value_zeth_units),
            h_sig=h_sig.hex(),
            phi=phi.hex())
        return (proof_inputs, signing_keypair)

    def create_mix_parameters_from_proof(
            self,
            mix_call_desc: MixCallDescription,
            prover_inputs: api.ProofInputs,
            signing_keypair: signing.SigningKeyPair,
            ext_proof: ExtendedProof,
            public_data: List[int],
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
        output_notes_with_k_pk: List[Tuple[api.ZethNote, EncryptionPublicKey]] = \
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
            public_data,
            for_dispatch_call)

        mix_params = MixParameters(
            ext_proof, public_data, signing_keypair.vk, signature, ciphertexts)
        return mix_params

    def create_mix_parameters_and_signing_key(
            self,
            prover_client: ProverClient,
            mk_tree: MerkleTree,
            sender_ownership_keypair: OwnershipKeyPair,
            sender_eth_address: str,
            inputs: List[Tuple[int, api.ZethNote]],
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
        assert len(mix_call_desc.inputs) == constants.JS_INPUTS
        assert len(mix_call_desc.outputs) == constants.JS_OUTPUTS

        prover_inputs, signing_keypair = MixerClient.create_prover_inputs(
            mix_call_desc)

        # pylint: disable=no-member
        assert len(prover_inputs.js_inputs) == constants.JS_INPUTS
        assert len(prover_inputs.js_outputs) == constants.JS_OUTPUTS
        # pylint: enable=no-member

        # Query the prover_server for the related proof
        ext_proof, public_data = prover_client.get_proof(prover_inputs)

        # Create the final MixParameters object
        mix_params = self.create_mix_parameters_from_proof(
            mix_call_desc,
            prover_inputs,
            signing_keypair,
            ext_proof,
            public_data,
            sender_eth_address,
            for_dispatch_call)

        return mix_params, signing_keypair


def encrypt_notes(
        notes: List[Tuple[api.ZethNote, EncryptionPublicKey]]) -> List[bytes]:
    """
    Encrypts a set of output notes to be decrypted by the respective receivers.
    Returns the ciphertexts corresponding to each note.
    """

    def _encrypt_note(
            out_note: api.ZethNote, pub_key: EncryptionPublicKey) -> bytes:
        out_note_bytes = proto_utils.zeth_note_to_bytes(out_note)

        return encrypt(out_note_bytes, pub_key)

    ciphertexts = [_encrypt_note(note, pk) for (note, pk) in notes]
    return ciphertexts


def receive_note(
        out_ev: MixOutputEvents,
        receiver_k_sk: EncryptionSecretKey
) -> Optional[Tuple[bytes, api.ZethNote]]:
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
        public_data: List[int],
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
        zksnark, pp, extproof, public_data)

    # If for_dispatch_call is set, omit proof from the signature. See
    # AbstractMixer.sol.
    if not for_dispatch_call:
        h.update(proof_bytes)

    h.update(pub_inputs_bytes)
    message_digest = h.digest()
    return signing.sign(signing_keypair.sk, message_digest)


def compute_commitment(zeth_note: api.ZethNote, pp: PairingParameters) -> bytes:
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
        zeth_note: api.ZethNote,
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
        nullifiers: List[bytes],
        sign_vk: JoinsplitSigVerificationKey) -> bytes:
    """
    Compute h_sig = sha256(nf_1 || ... || nf_{JS_INPUTS} || sign_vk)
    """
    h = sha256()
    for nf in nullifiers:
        h.update(nf)
    h.update(sign_vk.to_bytes())
    return h.digest()


def _create_api_zeth_notes(
        phi: bytes,
        hsig: bytes,
        outputs: List[Tuple[OwnershipPublicKey, int]]
) -> List[api.ZethNote]:
    """
    Create ordered list of api.ZethNote objects from the output descriptions.
    """
    def _create_api_zeth_note(
            out_index: int, recipient: OwnershipPublicKey, value: int
    ) -> api.ZethNote:
        rho = _compute_rho_i(phi, hsig, out_index)
        trap_r = _trap_r_randomness()
        return api.ZethNote(
            apk=ownership_key_as_hex(recipient),
            value=int64_to_hex(value),
            rho=rho.hex(),
            trap_r=trap_r)

    return [
        _create_api_zeth_note(idx, recipient, value)
        for idx, (recipient, value) in enumerate(outputs)]


def _proof_and_inputs_to_bytes(
        snark: IZKSnarkProvider,
        pp: PairingParameters,
        extproof: ExtendedProof,
        public_data: List[int]) -> Tuple[bytes, bytes]:
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
        message_to_bytes(public_data)


def _trap_r_randomness() -> str:
    """
    Compute randomness `r`
    """
    assert (constants.TRAPR_LENGTH_BYTES << 3) == constants.TRAPR_LENGTH
    return bytes(Random.get_random_bytes(constants.TRAPR_LENGTH_BYTES)).hex()


def _compute_rho_i(phi: bytes, hsig: bytes, i: int) -> bytes:
    """
    Returns
      rho_i = blake2s(0 || i || 10 || phi_truncated || hsig)
    where i is encoded in the smallest number of bits (index_bits) required to
    hold values 0, ..., JS_OUTPUTS-1, and phi_truncated is binary
    representation of phi, truncated to 256 - index_bits - 3 bits.

    See: Zcash protocol spec p. 57, Section 5.4.2 Pseudo Random Functions
    """
    assert i < constants.JS_OUTPUTS

    # Compute the number of bits required to represent the input index, and
    # truncate phi so that:
    #   left_leg = 0 || i || 10 || phi_truncated
    # occupies exactly 256 bits

    index_bits = math.ceil(math.log(constants.JS_OUTPUTS, 2))
    index_bin = f"{i:b}"
    index_bin = "0" * (index_bits - len(index_bin)) + index_bin
    assert len(index_bin) == index_bits, \
        f"index_bits: {index_bits}, index_bin: {index_bin}, i: {i}"

    phi_truncated_bits = 256 - 1 - index_bits - 2
    phi_truncated_bin = digest_to_binary_string(phi)[:phi_truncated_bits]
    assert len(phi_truncated_bin) == phi_truncated_bits

    left_leg_bin = "0" + index_bin + "10" + phi_truncated_bin
    assert len(left_leg_bin) == 256

    # Compute blake2s(left_leg || hsig)
    blake_hash = blake2s()
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
