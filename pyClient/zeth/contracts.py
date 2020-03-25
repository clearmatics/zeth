#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.encryption import EncryptionPublicKey, encode_encryption_public_key, \
    decode_encryption_public_key
from zeth.signing import SigningVerificationKey, Signature, \
    verification_key_as_mix_parameter, verification_key_from_mix_parameter, \
    signature_as_mix_parameter, signature_from_mix_parameter
from zeth.zksnark import IZKSnarkProvider, GenericProof, GenericVerificationKey
from zeth.utils import get_contracts_dir, hex_to_int
from zeth.constants import SOL_COMPILER_VERSION

import os
import json
import solcx
from typing import Dict, List, Iterator, Optional, Any

# Avoid trying to read too much data into memory
SYNC_BLOCKS_PER_BATCH = 10

Interface = Dict[str, Any]


class MixParameters:
    """
    Arguments to the mix call.
    """
    def __init__(
            self,
            extended_proof: GenericProof,
            signature_vk: SigningVerificationKey,
            signature: Signature,
            pk_sender: EncryptionPublicKey,
            ciphertexts: List[bytes]):
        self.extended_proof = extended_proof
        self.signature_vk = signature_vk
        self.signature = signature
        self.pk_sender = pk_sender
        self.ciphertexts = ciphertexts

    @staticmethod
    def from_json(params_json: str) -> MixParameters:
        return MixParameters._from_json_dict(json.loads(params_json))

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    def _to_json_dict(self) -> Dict[str, Any]:
        signature_vk_json = [
            str(x) for x in verification_key_as_mix_parameter(self.signature_vk)]
        signature_json = str(signature_as_mix_parameter(self.signature))
        pk_sender_json = encode_encryption_public_key(self.pk_sender).hex()
        ciphertexts_json = [x.hex() for x in self.ciphertexts]
        return {
            "extended_proof": self.extended_proof,
            "signature_vk": signature_vk_json,
            "signature": signature_json,
            "pk_sender": pk_sender_json,
            "ciphertexts": ciphertexts_json,
        }

    @staticmethod
    def _from_json_dict(json_dict: Dict[str, Any]) -> MixParameters:
        ext_proof = json_dict["extended_proof"]
        signature_pk_param = [int(x) for x in json_dict["signature_vk"]]
        signature_pk = verification_key_from_mix_parameter(signature_pk_param)
        signature = signature_from_mix_parameter(int(json_dict["signature"]))
        pk_sender = decode_encryption_public_key(
            bytes.fromhex(json_dict["pk_sender"]))
        ciphertexts = [bytes.fromhex(x) for x in json_dict["ciphertexts"]]
        return MixParameters(
            ext_proof, signature_pk, signature, pk_sender, ciphertexts)


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
            sender_k_pk: EncryptionPublicKey,
            output_events: List[MixOutputEvents]):
        self.new_merkle_root = new_merkle_root
        self.nullifiers = nullifiers
        self.sender_k_pk = sender_k_pk
        self.output_events = output_events


def _event_args_to_mix_result(event_args: Any) -> MixResult:
    mix_out_args = zip(event_args.commitments, event_args.ciphertexts)
    out_events = [MixOutputEvents(c, ciph) for (c, ciph) in mix_out_args]
    sender_k_pk = decode_encryption_public_key(event_args.pk_sender)
    return MixResult(
        new_merkle_root=event_args.root,
        nullifiers=event_args.nullifiers,
        sender_k_pk=sender_k_pk,
        output_events=out_events)


class InstanceDescription:
    """
    Minimal data required to instantiate the in-memory interface to a contract.
    """
    def __init__(self, address: str, abi: Dict[str, Any]):
        self.address = address
        self.abi = abi

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "abi": self.abi
        }

    @staticmethod
    def from_json_dict(desc_json: Dict[str, Any]) -> InstanceDescription:
        return InstanceDescription(desc_json["address"], desc_json["abi"])

    @staticmethod
    def from_instance(instance: Any) -> InstanceDescription:
        """
        Return the description of an existing deployed contract.
        """
        return InstanceDescription(instance.address, instance.abi)

    def instantiate(self, web3: Any) -> Any:
        """
        Return the instantiated contract
        """
        return web3.eth.contract(address=self.address, abi=self.abi)


def get_block_number(web3: Any) -> int:
    return web3.eth.blockNumber


def install_sol() -> None:
    solcx.install_solc(SOL_COMPILER_VERSION)


def compile_files(files: List[str]) -> Any:
    """
    Wrapper around solcx which ensures the required version of the compiler is
    used.
    """
    solcx.set_solc_version(SOL_COMPILER_VERSION)
    return solcx.compile_files(files, optimize=True)


def compile_mixer(zksnark: IZKSnarkProvider) -> Interface:
    contracts_dir = get_contracts_dir()
    mixer_name = zksnark.get_contract_name()
    path_to_mixer = os.path.join(contracts_dir, mixer_name + ".sol")
    compiled_sol = compile_files([path_to_mixer])
    return compiled_sol[path_to_mixer + ':' + mixer_name]


def deploy_mixer(
        web3: Any,
        mk_tree_depth: int,
        mixer_interface: Interface,
        vk: GenericVerificationKey,
        deployer_address: str,
        deployment_gas: int,
        token_address: str,
        zksnark: IZKSnarkProvider) -> Any:
    """
    Common function to deploy a mixer contract. Returns the mixer and the
    initial merkle root of the commitment tree
    """
    # Deploy the Mixer
    mixer = web3.eth.contract(
        abi=mixer_interface['abi'], bytecode=mixer_interface['bin'])

    verification_key_params = zksnark.verification_key_parameters(vk)
    tx_hash = mixer.constructor(
        mk_depth=mk_tree_depth,
        token=token_address,
        **verification_key_params
    ).transact({'from': deployer_address, 'gas': deployment_gas})
    # Get tx receipt to get Mixer contract address
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash, 10000)
    mixer_address = tx_receipt['contractAddress']
    gas_used = tx_receipt.gasUsed
    status = tx_receipt.status
    print(f"{tx_hash[0:8]}: gasUsed={gas_used}, status={status}")
    # Get the mixer contract instance
    return web3.eth.contract(
        address=mixer_address,
        abi=mixer_interface['abi']
    )


def deploy_tree_contract(
        web3: Any,
        interface: Interface,
        depth: int,
        hasher_address: str,
        account: str) -> Any:
    """
    Deploy tree contract
    """
    contract = web3.eth.contract(abi=interface['abi'], bytecode=interface['bin'])
    tx_hash = contract \
        .constructor(hasher_address, depth) \
        .transact({'from': account})
    # Get tx receipt to get Mixer contract address
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash, 10000)
    address = tx_receipt['contractAddress']
    # Get the mixer contract instance
    instance = web3.eth.contract(
        address=address,
        abi=interface['abi']
    )
    return instance


def mix(
        zksnark: IZKSnarkProvider,
        mixer_instance: Any,
        mix_parameters: MixParameters,
        sender_address: str,
        wei_pub_value: int,
        call_gas: int) -> str:
    """
    Run the mixer
    """
    # Convert all params to the correct form for calling the mix method.
    proof_param = zksnark.mixer_proof_parameters(mix_parameters.extended_proof)
    proof_inputs_param = hex_to_int(mix_parameters.extended_proof["inputs"])
    vk_param = verification_key_as_mix_parameter(mix_parameters.signature_vk)
    signature_param = signature_as_mix_parameter(mix_parameters.signature)
    pk_sender_param = encode_encryption_public_key(mix_parameters.pk_sender)
    ciphertexts_param = mix_parameters.ciphertexts
    tx_hash = mixer_instance.functions.mix(
        *proof_param,
        vk_param,
        signature_param,
        proof_inputs_param,
        pk_sender_param,
        ciphertexts_param
    ).transact({'from': sender_address, 'value': wei_pub_value, 'gas': call_gas})
    return tx_hash.hex()


def parse_mix_call(
        mixer_instance: Any,
        _tx_receipt: str) -> MixResult:
    """
    Get the logs data associated with this mixing
    """
    log_mix_filter = mixer_instance.eventFilter("LogMix", {'fromBlock': 'latest'})
    log_mix_events = log_mix_filter.get_all_entries()
    mix_results = [_event_args_to_mix_result(ev.args) for ev in log_mix_events]
    return mix_results[0]


def _next_nullifier_or_none(nullifier_iter: Iterator[bytes]) -> Optional[Any]:
    try:
        return next(nullifier_iter)
    except StopIteration:
        return None


def get_mix_results(
        web3: Any,
        mixer_instance: Any,
        start_block: int,
        end_block: int) -> Iterator[MixResult]:
    """
    Iterator for all events generated by 'mix' executions, over some block
    range. Batches eth RPC calls to avoid holding huge numbers of events in
    memory.
    """
    for batch_start in range(start_block, end_block + 1, SYNC_BLOCKS_PER_BATCH):
        # Get mk_root, address and ciphertext filters for
        try:
            filter_params = {
                'fromBlock': batch_start,
                'toBlock': batch_start + SYNC_BLOCKS_PER_BATCH - 1,
            }
            log_mix_filter = mixer_instance.eventFilter("LogMix", filter_params)
            for log_mix_event in log_mix_filter.get_all_entries():
                yield _event_args_to_mix_result(log_mix_event.args)

        finally:
            web3.eth.uninstallFilter(log_mix_filter.filter_id)
