#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.core.signing import SigningVerificationKey, Signature, \
    verification_key_as_mix_parameter, verification_key_from_mix_parameter, \
    signature_as_mix_parameter, signature_from_mix_parameter
from zeth.core.pairing import PairingParameters
from zeth.core.zksnark import IZKSnarkProvider, ExtendedProof
from zeth.core.utils import EtherValue, hex_list_to_uint256_list
from zeth.core.constants import SOL_COMPILER_VERSION
from web3.utils.contracts import find_matching_event_abi  # type: ignore
from web3.utils.events import get_event_data  # type: ignore
import json
import solcx
import traceback
from typing import Dict, List, Iterator, Optional, Union, Iterable, Any

# Avoid trying to read too much data into memory
SYNC_BLOCKS_PER_BATCH = 1000

Interface = Dict[str, Any]


class MixParameters:
    """
    Arguments to the mix call.
    """
    def __init__(
            self,
            extended_proof: ExtendedProof,
            signature_vk: SigningVerificationKey,
            signature: Signature,
            ciphertexts: List[bytes]):
        self.extended_proof = extended_proof
        self.signature_vk = signature_vk
        self.signature = signature
        self.ciphertexts = ciphertexts

    @staticmethod
    def from_json(zksnark: IZKSnarkProvider, params_json: str) -> MixParameters:
        return MixParameters._from_json_dict(zksnark, json.loads(params_json))

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    def _to_json_dict(self) -> Dict[str, Any]:
        ext_proof_json = self.extended_proof.to_json_dict()
        signature_vk_json = [
            str(x) for x in verification_key_as_mix_parameter(self.signature_vk)]
        signature_json = str(signature_as_mix_parameter(self.signature))
        ciphertexts_json = [x.hex() for x in self.ciphertexts]
        return {
            "extended_proof": ext_proof_json,
            "signature_vk": signature_vk_json,
            "signature": signature_json,
            "ciphertexts": ciphertexts_json,
        }

    @staticmethod
    def _from_json_dict(
            zksnark: IZKSnarkProvider,
            json_dict: Dict[str, Any]) -> MixParameters:
        ext_proof = ExtendedProof.from_json_dict(
            zksnark, json_dict["extended_proof"])
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
            deployer_eth_address: str,
            deployer_eth_private_key: Optional[bytes],
            deployment_gas: int,
            compiler_flags: Dict[str, Any] = None,
            args: Iterable[Any] = None) -> InstanceDescription:
        """
        Compile and deploy a contract, returning the live instance and an instance
        description (which the caller should save in order to access the
        instance in the future).
        """
        compiled = InstanceDescription.compile(
            source_file, contract_name, compiler_flags)
        assert compiled
        instance_desc = InstanceDescription.deploy_from_compiled(
            web3,
            deployer_eth_address,
            deployer_eth_private_key,
            deployment_gas,
            compiled,
            *(args or []))
        print(
            f"deploy: contract: {contract_name} "
            f"to address: {instance_desc.address}")
        return instance_desc

    @staticmethod
    def deploy_from_compiled(
            web3: Any,
            deployer_eth_address: str,
            deployer_eth_private_key: Optional[bytes],
            deployment_gas: int,
            compiled: Any,
            *args: Any) -> InstanceDescription:
        contract = web3.eth.contract(
            abi=compiled['abi'], bytecode=compiled['bin'])
        construct_call = contract.constructor(*args)
        tx_hash = send_contract_call(
            web3,
            construct_call,
            deployer_eth_address,
            deployer_eth_private_key,
            None,
            deployment_gas)

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
        verification_key_as_mix_parameter(mix_parameters.signature_vk),
        signature_as_mix_parameter(mix_parameters.signature),
        hex_list_to_uint256_list(mix_parameters.extended_proof.inputs),
        mix_parameters.ciphertexts,
    ]


def _create_web3_mixer_call(
        zksnark: IZKSnarkProvider,
        pp: PairingParameters,
        mixer_instance: Any,
        mix_parameters: MixParameters) -> Any:
    mix_params_eth = mix_parameters_as_contract_arguments(
        zksnark, pp, mix_parameters)
    return mixer_instance.functions.mix(*mix_params_eth)


def mix_call(
        zksnark: IZKSnarkProvider,
        pp: PairingParameters,
        mixer_instance: Any,
        mix_parameters: MixParameters,
        sender_address: str,
        wei_pub_value: int,
        call_gas: int) -> bool:
    """
    Call the mix method (executes on the RPC host, without creating a
    transaction). Returns True if the call succeeds.  False, otherwise.
    """
    mixer_call = _create_web3_mixer_call(
        zksnark, pp, mixer_instance, mix_parameters)
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
        web3: Any,
        zksnark: IZKSnarkProvider,
        pp: PairingParameters,
        mixer_instance: Any,
        mix_parameters: MixParameters,
        sender_address: str,
        sender_private_key: Optional[bytes],
        pub_value: Optional[EtherValue],
        call_gas: Optional[int]) -> str:
    """
    Create and broadcast a transaction that calls the mix method of the Mixer
    """
    mixer_call = _create_web3_mixer_call(
        zksnark, pp, mixer_instance, mix_parameters)
    tx_hash = send_contract_call(
        web3, mixer_call, sender_address, sender_private_key, pub_value, call_gas)
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
        end_block: int,
        batch_size: Optional[int] = None) -> Iterator[MixResult]:
    """
    Iterator for all events generated by 'mix' executions, over some block
    range (inclusive of `end_block`). Batch eth RPC calls to avoid too many
    calls, and holding huge lists of events in memory.
    """
    contract_address = mixer_instance.address
    event_abi = find_matching_event_abi(mixer_instance.abi, event_name="LogMix")
    batch_size = batch_size or SYNC_BLOCKS_PER_BATCH

    while start_block <= end_block:
        # Filters are *inclusive* wrt "toBlock", hence the -1 here, and + 1 to
        # set start_block before iterating.
        to_block = min(start_block + batch_size - 1, end_block)
        filter_params = {
            'fromBlock': start_block,
            'toBlock': to_block,
            'address': contract_address,
        }
        logs = web3.eth.getLogs(filter_params)
        for log in logs:
            event_data = get_event_data(event_abi, log)
            yield _event_args_to_mix_result(event_data.args)
        start_block = to_block + 1


def send_contract_call(
        web3: Any,
        call: Any,
        sender_eth_addr: str,
        sender_eth_private_key: Optional[bytes] = None,
        value: Optional[EtherValue] = None,
        gas: Optional[int] = None) -> bytes:
    """
    Broadcast a transaction for a contract call, handling the difference
    between hosted keys (sender_eth_private_key is None) and local keys
    (sender_eth_private_key is not None). Returns the hash of the broadcast
    transaction.

    """
    tx_desc: Dict[str, Union[str, int]] = {'from': sender_eth_addr}
    if value:
        tx_desc["value"] = value.wei
    if gas:
        tx_desc["gas"] = gas
    if sender_eth_private_key:
        tx_desc["gasPrice"] = web3.eth.gasPrice
        tx_desc["nonce"] = web3.eth.getTransactionCount(sender_eth_addr)
        transaction = call.buildTransaction(tx_desc)
        signed_tx = web3.eth.account.signTransaction(
            transaction, sender_eth_private_key)
        return web3.eth.sendRawTransaction(signed_tx.rawTransaction)

    # Hosted path
    return call.transact(tx_desc)
