#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
import zeth.constants as constants
from zeth.encryption import EncryptionPublicKey, encode_encryption_public_key
from zeth.signing import SigningVerificationKey
from zeth.zksnark import IZKSnarkProvider, GenericProof, GenericVerificationKey
from zeth.utils import get_contracts_dir, hex_to_int, get_public_key_from_bytes

import os
import json
from web3 import Web3, HTTPProvider  # type: ignore
from solcx import compile_files  # type: ignore
from typing import Tuple, Dict, List, Iterator, Optional, Any

W3 = Web3(HTTPProvider(constants.WEB3_HTTP_PROVIDER))
# pylint is not aware of W3.eth. This prevents it from complaining.
eth = W3.eth  # pylint: disable=no-member, invalid-name

# Avoid trying to read too much data into memory
SYNC_BLOCKS_PER_BATCH = 10


Interface = Dict[str, Any]

# List of address and cipher text pairs
EncryptedNote = Tuple[int, bytes]


class MixResult:
    """
    Data structure representing the result of the mix call.
    """
    def __init__(
            self,
            encrypted_notes: List[EncryptedNote],
            new_merkle_root: str,
            sender_k_pk: EncryptionPublicKey):
        self.encrypted_notes = encrypted_notes
        self.new_merkle_root = new_merkle_root
        self.sender_k_pk = sender_k_pk


class InstanceDescription:
    """
    Minimal data required to instantiate the in-memory interface to a contract.
    """
    def __init__(self, address: str, abi: Dict[str, Any]):
        self.address = address
        self.abi = abi

    def to_json(self) -> str:
        return json.dumps(
            {"address": self.address, "abi": self.abi},
            indent=4)

    @staticmethod
    def from_json(json_str: str) -> InstanceDescription:
        desc_json = json.loads(json_str)
        return InstanceDescription(desc_json["address"], desc_json["abi"])


def contract_instance(desc: InstanceDescription) -> Any:
    """
    Return a contract instance, given the address and abi
    """
    return eth.contract(address=desc.address, abi=desc.abi)


def contract_description(instance: Any) -> InstanceDescription:
    """
    Return the description of a deployed contract (which can be used to
    reinstantiate it).
    """
    return InstanceDescription(instance.address, instance.abi)


def get_block_number() -> int:
    return eth.blockNumber


def compile_contracts(
        zksnark: IZKSnarkProvider) -> Tuple[Interface, Interface, Interface]:
    contracts_dir = get_contracts_dir()
    (proof_verifier_name, mixer_name) = zksnark.get_contract_names()
    otsig_verifier_name = constants.SCHNORR_VERIFIER_CONTRACT

    path_to_proof_verifier = os.path.join(
        contracts_dir, proof_verifier_name + ".sol")
    path_to_otsig_verifier = os.path.join(
        contracts_dir, otsig_verifier_name + ".sol")
    path_to_mixer = os.path.join(contracts_dir, mixer_name + ".sol")

    compiled_sol = compile_files(
        [path_to_proof_verifier, path_to_otsig_verifier, path_to_mixer])

    proof_verifier_interface = \
        compiled_sol[path_to_proof_verifier + ':' + proof_verifier_name]
    otsig_verifier_interface = \
        compiled_sol[path_to_otsig_verifier + ':' + otsig_verifier_name]
    mixer_interface = compiled_sol[path_to_mixer + ':' + mixer_name]

    return (proof_verifier_interface, otsig_verifier_interface, mixer_interface)


def compile_util_contracts() -> Tuple[Interface, Interface]:
    contracts_dir = get_contracts_dir()
    path_to_pairing = os.path.join(contracts_dir, "Pairing.sol")
    path_to_bytes = os.path.join(contracts_dir, "Bytes.sol")
    path_to_mimc7 = os.path.join(contracts_dir, "MiMC7.sol")
    path_to_tree = os.path.join(contracts_dir, "MerkleTreeMiMC7.sol")
    compiled_sol = compile_files(
        [path_to_pairing, path_to_bytes, path_to_mimc7, path_to_tree])
    mimc_interface = compiled_sol[path_to_mimc7 + ':' + "MiMC7"]
    tree_interface = compiled_sol[path_to_tree + ':' + "MerkleTreeMiMC7"]
    return mimc_interface, tree_interface


def deploy_mixer(
        proof_verifier_address: str,
        otsig_verifier_address: str,
        mixer_interface: Interface,
        mk_tree_depth: int,
        deployer_address: str,
        deployment_gas: int,
        token_address: str,
        hasher_address: str) -> Tuple[Any, str]:
    """
    Common function to deploy a mixer contract. Returns the mixer and the
    initial merkle root of the commitment tree
    """
    # Deploy the Mixer contract once the Verifier is successfully deployed
    mixer = eth.contract(
        abi=mixer_interface['abi'], bytecode=mixer_interface['bin'])

    tx_hash = mixer.constructor(
        snark_ver=proof_verifier_address,
        sig_ver=otsig_verifier_address,
        mk_depth=mk_tree_depth,
        token=token_address,
        hasher=hasher_address
    ).transact({'from': deployer_address, 'gas': deployment_gas})
    # Get tx receipt to get Mixer contract address
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    mixer_address = tx_receipt['contractAddress']
    # Get the mixer contract instance
    mixer = eth.contract(
        address=mixer_address,
        abi=mixer_interface['abi']
    )
    # Get the initial merkle root to proceed to the first payments
    ef_log_merkle_root = \
        mixer.eventFilter("LogMerkleRoot", {'fromBlock': 'latest'})
    event_logs_log_merkle_root = ef_log_merkle_root.get_all_entries()
    initial_root = W3.toHex(event_logs_log_merkle_root[0].args.root)[2:]
    return(mixer, initial_root)


def deploy_otschnorr_contracts(
        verifier: Any,
        deployer_address: str,
        deployment_gas: int) -> str:
    """
    Deploy the verifier used with OTSCHNORR
    """
    # Deploy the verifier contract with the good verification key
    tx_hash = verifier.constructor().transact(
            {'from': deployer_address, 'gas': deployment_gas})

    # Get tx receipt to get Verifier contract address
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    verifier_address = tx_receipt['contractAddress']
    return verifier_address


def deploy_contracts(
        mk_tree_depth: int,
        proof_verifier_interface: Interface,
        otsig_verifier_interface: Interface,
        mixer_interface: Interface,
        hasher_interface: Interface,
        vk: GenericVerificationKey,
        deployer_address: str,
        deployment_gas: int,
        token_address: str,
        zksnark: IZKSnarkProvider) -> Tuple[Any, str]:
    """
    Deploy the mixer contract with the given merkle tree depth and returns an
    instance of the mixer along with the initial merkle tree root to use for
    the first zero knowledge payments
    """
    # Deploy the proof verifier contract with the good verification key
    proof_verifier = eth.contract(
        abi=proof_verifier_interface['abi'],
        bytecode=proof_verifier_interface['bin']
    )

    verifier_constr_params = zksnark.verifier_constructor_parameters(vk)
    tx_hash = proof_verifier.constructor(**verifier_constr_params) \
        .transact({'from': deployer_address, 'gas': deployment_gas})
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    proof_verifier_address = tx_receipt['contractAddress']

    # Deploy MiMC contract
    _, hasher_address = deploy_mimc_contract(hasher_interface)  # type: ignore

    # Deploy the one-time signature verifier contract
    otsig_verifier = eth.contract(
        abi=otsig_verifier_interface['abi'],
        bytecode=otsig_verifier_interface['bin'])
    otsig_verifier_address = deploy_otschnorr_contracts(
            otsig_verifier, deployer_address, deployment_gas)

    return deploy_mixer(
            proof_verifier_address,
            otsig_verifier_address,
            mixer_interface,
            mk_tree_depth,
            deployer_address,
            deployment_gas,
            token_address,
            hasher_address)


def deploy_mimc_contract(interface: Interface) -> Tuple[Any, str]:
    """
    Deploy mimc contract
    """
    contract = eth.contract(abi=interface['abi'], bytecode=interface['bin'])
    tx_hash = contract.constructor().transact({'from': eth.accounts[1]})
    # Get tx receipt to get Mixer contract address
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    address = tx_receipt['contractAddress']
    # Get the mixer contract instance
    instance = eth.contract(
        address=address,
        abi=interface['abi']
    )
    return instance, address


def deploy_tree_contract(
        interface: Interface,
        depth: int,
        hasher_address: str) -> Any:
    """
    Deploy tree contract
    """
    contract = eth.contract(abi=interface['abi'], bytecode=interface['bin'])
    tx_hash = contract \
        .constructor(hasher_address, depth) \
        .transact({'from': eth.accounts[1]})
    # Get tx receipt to get Mixer contract address
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    address = tx_receipt['contractAddress']
    # Get the mixer contract instance
    instance = eth.contract(
        address=address,
        abi=interface['abi']
    )
    return instance


def mix(
        mixer_instance: Any,
        pk_sender: EncryptionPublicKey,
        ciphertext1: bytes,
        ciphertext2: bytes,
        parsed_proof: GenericProof,
        vk: SigningVerificationKey,
        sigma: int,
        sender_address: str,
        wei_pub_value: int,
        call_gas: int,
        zksnark: IZKSnarkProvider) -> MixResult:
    """
    Run the mixer
    """
    pk_sender_encoded = encode_encryption_public_key(pk_sender)
    proof_params = zksnark.mixer_proof_parameters(parsed_proof)
    tx_hash = mixer_instance.functions.mix(
        *proof_params,
        [[int(vk.ppk[0]), int(vk.ppk[1])], [int(vk.spk[0]), int(vk.spk[1])]],
        sigma,
        hex_to_int(parsed_proof["inputs"]),
        pk_sender_encoded,
        ciphertext1,
        ciphertext2,
    ).transact({'from': sender_address, 'value': wei_pub_value, 'gas': call_gas})
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 10000)
    return parse_mix_call(mixer_instance, tx_receipt)


def parse_mix_call(
        mixer_instance: Any,
        _tx_receipt: str) -> MixResult:
    """
    Get the logs data associated with this mixing
    """
    # Gather the addresses of the appended commitments
    event_filter_log_address = mixer_instance.eventFilter(
        "LogAddress",
        {'fromBlock': 'latest'})
    event_logs_log_address = event_filter_log_address.get_all_entries()
    # Get the new merkle root
    event_filter_log_merkle_root = mixer_instance.eventFilter(
        "LogMerkleRoot", {'fromBlock': 'latest'})
    event_logs_log_merkle_root = event_filter_log_merkle_root.get_all_entries()
    # Get the ciphertexts
    event_filter_log_secret_ciphers = mixer_instance.eventFilter(
        "LogSecretCiphers", {'fromBlock': 'latest'})
    event_logs_log_secret_ciphers = \
        event_filter_log_secret_ciphers.get_all_entries()
    new_merkle_root = W3.toHex(event_logs_log_merkle_root[0].args.root)[2:]
    sender_k_pk_bytes = event_logs_log_secret_ciphers[0].args.pk_sender

    encrypted_notes = _extract_encrypted_notes_from_logs(
        event_logs_log_address, event_logs_log_secret_ciphers)

    return MixResult(
        encrypted_notes=encrypted_notes,
        new_merkle_root=new_merkle_root,
        sender_k_pk=get_public_key_from_bytes(sender_k_pk_bytes))


def _next_commit_or_none(
        address_iter: Iterator[Optional[Any]],
        ciphertext_iter: Iterator[Optional[Any]]
) -> Tuple[Optional[Any], Optional[Any]]:
    """
    Zip the  address and ciphertext iterators.   Avoid StopIteration exceptions,
    so the caller can rely on reading one entry ahead.
    """
    # Assume that the two input iterators are of the same length.
    try:
        address = next(address_iter)
    except StopIteration:
        return None, None
    return address, next(ciphertext_iter)


def _parse_events(
        merkle_root_events: List[Any],
        commit_address_events: List[Any],
        ciphertext_events: List[Any]) -> Iterator[MixResult]:
    """
    Receive lists of events from the merkle, address and ciphertext filters,
    grouping them correctly as a MixResult per Transaction.  (This is
    non-trivial, because there may be multiple address and ciphertext events per
    new merkle root.
    """
    assert len(commit_address_events) == len(ciphertext_events)
    assert len(commit_address_events) >= len(merkle_root_events)

    commit_address_iter = iter(commit_address_events)
    ciphertext_iter = iter(ciphertext_events)

    address, ciphertext = _next_commit_or_none(
        commit_address_iter, ciphertext_iter)
    for mk_root_event in merkle_root_events:
        assert address is not None
        assert ciphertext is not None

        tx_hash = mk_root_event.transactionHash
        mk_root = mk_root_event.args.root
        sender_k_pk_bytes = ciphertext.args.pk_sender
        enc_notes: List[Tuple[int, bytes]] = []
        while address and address.transactionHash == tx_hash:
            assert ciphertext.transactionHash == tx_hash
            enc_notes.append(
                (address.args.commAddr, ciphertext.args.ciphertext))
            address, ciphertext = _next_commit_or_none(
                commit_address_iter, ciphertext_iter)
        yield MixResult(
            encrypted_notes=enc_notes,
            new_merkle_root=mk_root,
            sender_k_pk=get_public_key_from_bytes(sender_k_pk_bytes))

    assert address is None
    assert ciphertext is None


def get_mix_results(
        mixer_instance: Any,
        start_block: int,
        end_block: int) -> Iterator[MixResult]:
    """
    Iterator for all events generated by 'mix' executions, over some block
    range.  Batches eth RPC calls to avoid holding huge numbers of
    """
    for batch_start in range(start_block, end_block + 1, SYNC_BLOCKS_PER_BATCH):
        # Get mk_root, address and ciphertext filters for
        try:
            filter_params = {
                'fromBlock': batch_start,
                'toBlock': batch_start + SYNC_BLOCKS_PER_BATCH - 1
            }
            merkle_root_filter = mixer_instance.eventFilter(
                "LogMerkleRoot", filter_params)
            address_filter = mixer_instance.eventFilter(
                "LogAddress", filter_params)
            ciphertext_filter = mixer_instance.eventFilter(
                "LogSecretCiphers", filter_params)

            for entry in _parse_events(
                    merkle_root_filter.get_all_entries(),
                    address_filter.get_all_entries(),
                    ciphertext_filter.get_all_entries()):
                yield entry

        finally:
            eth.uninstallFilter(merkle_root_filter.filter_id)
            eth.uninstallFilter(address_filter.filter_id)
            eth.uninstallFilter(ciphertext_filter.filter_id)


def _extract_encrypted_notes_from_logs(
        log_addresses: List[Any],
        log_ciphertexts: List[Any]) -> List[Tuple[int, bytes]]:
    assert len(log_addresses) == len(log_ciphertexts)
    return [(log_addr.args.commAddr, log_ciph.args.ciphertext) for
            log_addr, log_ciph in zip(log_addresses, log_ciphertexts)]


def mimc_hash(instance: Any, m: bytes, k: bytes, seed: bytes) -> bytes:
    """
    Call the hash method of MiMC contract
    """
    return instance.functions.hash(m, k, seed).call()


def get_merkle_tree(mixer_instance: Any) -> List[bytes]:
    """
    Return the Merkle tree
    """
    return mixer_instance.functions.getTree().call()


def get_merkle_root(mixer_instance: Any) -> bytes:
    """
    Return the Merkle tree root
    """
    return mixer_instance.functions.getRoot().call()
