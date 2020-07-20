#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.signing import SigningVerificationKey, Signature, \
    verification_key_as_mix_parameter, verification_key_from_mix_parameter, \
    signature_as_mix_parameter, signature_from_mix_parameter
from zeth.zksnark import IZKSnarkProvider, GenericProof
from zeth.utils import EtherValue, hex_to_int
from zeth.constants import SOL_COMPILER_VERSION
import json
import solcx
import traceback
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
            ciphertexts: List[bytes]):
        self.extended_proof = extended_proof
        self.signature_vk = signature_vk
        self.signature = signature
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
        ciphertexts_json = [x.hex() for x in self.ciphertexts]
        return {
            "extended_proof": self.extended_proof,
            "signature_vk": signature_vk_json,
            "signature": signature_json,
            "ciphertexts": ciphertexts_json,
        }

    @staticmethod
    def _from_json_dict(json_dict: Dict[str, Any]) -> MixParameters:
        ext_proof = json_dict["extended_proof"]
        signature_pk_param = [int(x) for x in json_dict["signature_vk"]]
        signature_pk = verification_key_from_mix_parameter(signature_pk_param)
        signature = signature_from_mix_parameter(int(json_dict["signature"]))
        ciphertexts = [bytes.fromhex(x) for x in json_dict["ciphertexts"]]
        return MixParameters(
            ext_proof, signature_pk, signature, ciphertexts)


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


def _event_args_to_mix_result(event_args: Any) -> MixResult:
    mix_out_args = zip(event_args.commitments, event_args.ciphertexts)
    out_events = [MixOutputEvents(c, ciph) for (c, ciph) in mix_out_args]
    return MixResult(
        new_merkle_root=event_args.root,
        nullifiers=event_args.nullifiers,
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
    def deploy(
            web3: Any,
            source_file: str,
            contract_name: str,
            deployer_address: str,
            deployment_gas: EtherValue,
            compiler_flags: Dict[str, Any] = None,
            **kwargs: Any) -> InstanceDescription:
        """
        Compile and deploy a contract, returning the live instance and an instance
        description (which the caller should save in order to access the
        instance in the future).
        """
        compiled = InstanceDescription.compile(
            source_file, contract_name, compiler_flags)
        assert compiled
        instance_desc = InstanceDescription.deploy_from_compiled(
            web3, deployer_address, deployment_gas, compiled, **kwargs)
        print(
            f"deploy: contract: {contract_name} "
            f"to address: {instance_desc.address}")
        return instance_desc

    @staticmethod
    def deploy_from_compiled(
            web3: Any,
            deployer_address: str,
            deployment_gas: EtherValue,
            compiled: Any,
            **kwargs: Any) -> InstanceDescription:
        contract = web3.eth.contract(
            abi=compiled['abi'], bytecode=compiled['bin'])
        tx_hash = contract.constructor(**kwargs).transact({
            'from': deployer_address,
            'gas': deployment_gas.wei
        })
        tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash, 10000)
        contract_address = tx_receipt['contractAddress']
        print(
            f"deploy:   tx_hash={tx_hash[0:8].hex()}, " +
            f"  gasUsed={tx_receipt.gasUsed}, status={tx_receipt.status}")
        return InstanceDescription(contract_address, compiled['abi'])

    @staticmethod
    def compile(
            source_file: str,
            contract_name: str,
            compiler_flags: Dict[str, Any] = None) \
            -> Any:
        compiled_all = compile_files([source_file], **(compiler_flags or {}))
        assert compiled_all
        compiled = compiled_all[f"{source_file}:{contract_name}"]
        assert compiled
        return compiled

    def instantiate(self, web3: Any) -> Any:
        """
        Return the instantiated contract
        """
        return web3.eth.contract(address=self.address, abi=self.abi)


def get_block_number(web3: Any) -> int:
    return web3.eth.blockNumber


def install_sol() -> None:
    solcx.install_solc(SOL_COMPILER_VERSION)


def compile_files(files: List[str], **kwargs: Any) -> Any:
    """
    Wrapper around solcx which ensures the required version of the compiler is
    used.
    """
    solcx.set_solc_version(SOL_COMPILER_VERSION)
    return solcx.compile_files(files, optimize=True, **kwargs)


def mix_parameters_as_contract_arguments(
        zksnark: IZKSnarkProvider,
        mix_parameters: MixParameters) -> List[Any]:
    """
    Convert MixParameters to a list of eth ABI objects which can be passed to
    the contract's mix method.
    """
    proof_params: List[Any] = zksnark.mixer_proof_parameters(
        mix_parameters.extended_proof)
    proof_params.extend([
        verification_key_as_mix_parameter(mix_parameters.signature_vk),
        signature_as_mix_parameter(mix_parameters.signature),
        hex_to_int(mix_parameters.extended_proof["inputs"]),
        mix_parameters.ciphertexts
    ])
    return proof_params


def _create_web3_mixer_call(
        zksnark: IZKSnarkProvider,
        mixer_instance: Any,
        mix_parameters: MixParameters) -> Any:
    mix_params_eth = mix_parameters_as_contract_arguments(zksnark, mix_parameters)
    return mixer_instance.functions.mix(*mix_params_eth)


def mix_call(
        zksnark: IZKSnarkProvider,
        mixer_instance: Any,
        mix_parameters: MixParameters,
        sender_address: str,
        wei_pub_value: int,
        call_gas: int) -> bool:
    """
    Call the mix method (executes on the RPC host, without creating a
    transaction). Returns True if the call succeeds.  False, otherwise.
    """
    mixer_call = _create_web3_mixer_call(zksnark, mixer_instance, mix_parameters)
    try:
        mixer_call.call({
            'from': sender_address,
            'value': wei_pub_value,
            'gas': call_gas
        })
        return True

    except ValueError:
        print("error executing mix call:")
        traceback.print_exc()

    return False


def mix(
        zksnark: IZKSnarkProvider,
        mixer_instance: Any,
        mix_parameters: MixParameters,
        sender_address: str,
        wei_pub_value: int,
        call_gas: int) -> str:
    """
    Create and broadcast a transaction that calls the mix method of the Mixer
    """
    mixer_call = _create_web3_mixer_call(zksnark, mixer_instance, mix_parameters)
    tx_hash = mixer_call.transact({
        'from': sender_address,
        'value': wei_pub_value,
        'gas': call_gas
    })
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
