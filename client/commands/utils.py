# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from commands.constants import WALLET_USERNAME, ETH_ADDRESS_DEFAULT
from zeth.zeth_address import ZethAddressPub, ZethAddressPriv, ZethAddress
from zeth.contracts import \
    InstanceDescription, get_block_number, get_mix_results, compile_files
from zeth.mixer_client import MixerClient
from zeth.utils import \
    open_web3, short_commitment, EtherValue, get_zeth_dir, from_zeth_units
from zeth.wallet import ZethNoteDescription, Wallet
from click import ClickException
import json
from os.path import exists, join
from typing import Dict, Tuple, Optional, Callable, Any
from web3 import Web3  # type: ignore


class ClientConfig:
    """
    Context for users of these client tools
    """
    def __init__(
            self,
            eth_rpc_endpoint: str,
            prover_server_endpoint: str,
            instance_file: str,
            address_file: str,
            wallet_dir: str):
        self.eth_rpc_endpoint = eth_rpc_endpoint
        self.prover_server_endpoint = prover_server_endpoint
        self.instance_file = instance_file
        self.address_file = address_file
        self.wallet_dir = wallet_dir


def open_web3_from_ctx(ctx: ClientConfig) -> Any:
    return open_web3(ctx.eth_rpc_endpoint)


class MixerDescription:
    """
    Holds an InstanceDescription for the mixer contract, and optionally an
    InstanceDescription for the token contract.
    """
    def __init__(
            self,
            mixer: InstanceDescription,
            token: Optional[InstanceDescription]):
        self.mixer = mixer
        self.token = token

    def to_json(self) -> str:
        json_dict = {
            "mixer": self.mixer.to_json_dict()
        }
        if self.token:
            json_dict["token"] = self.token.to_json_dict()
        return json.dumps(json_dict)

    @staticmethod
    def from_json(json_str: str) -> MixerDescription:
        json_dict = json.loads(json_str)
        mixer = InstanceDescription.from_json_dict(json_dict["mixer"])
        token_dict = json_dict.get("token", None)
        token = InstanceDescription.from_json_dict(token_dict) \
            if token_dict else None
        return MixerDescription(mixer, token)


def get_erc20_abi() -> Dict[str, Any]:
    zeth_dir = get_zeth_dir()
    openzeppelin_dir = join(
        zeth_dir, "zeth_contracts", "node_modules", "openzeppelin-solidity")
    ierc20_path = join(
        openzeppelin_dir, "contracts", "token", "ERC20", "IERC20.sol")
    compiled_sol = compile_files([ierc20_path])
    erc20_interface = compiled_sol[ierc20_path + ":IERC20"]
    return erc20_interface["abi"]


def get_erc20_instance_description(token_address: str) -> InstanceDescription:
    return InstanceDescription(token_address, get_erc20_abi())


def write_mixer_description(
        mixer_desc_file: str,
        mixer_desc: MixerDescription) -> None:
    """
    Write the mixer (and token) instance information
    """
    with open(mixer_desc_file, "w") as instance_f:
        instance_f.write(mixer_desc.to_json())


def load_mixer_description(mixer_description_file: str) -> MixerDescription:
    """
    Return mixer and token (if present) contract instances
    """
    with open(mixer_description_file, "r") as desc_f:
        return MixerDescription.from_json(desc_f.read())


def load_mixer_description_from_ctx(ctx: ClientConfig) -> MixerDescription:
    return load_mixer_description(ctx.instance_file)


def get_zeth_address_file(ctx: ClientConfig) -> str:
    return ctx.address_file


def load_zeth_address_public(ctx: ClientConfig) -> ZethAddressPub:
    """
    Load a ZethAddressPub from a key file.
    """
    secret_key_file = get_zeth_address_file(ctx)
    pub_addr_file = pub_address_file(secret_key_file)
    with open(pub_addr_file, "r") as pub_addr_f:
        return ZethAddressPub.parse(pub_addr_f.read())


def write_zeth_address_public(
        pub_addr: ZethAddressPub, pub_addr_file: str) -> None:
    """
    Write a ZethAddressPub to a file
    """
    with open(pub_addr_file, "w") as pub_addr_f:
        pub_addr_f.write(str(pub_addr))


def load_zeth_address_secret(ctx: ClientConfig) -> ZethAddressPriv:
    """
    Read ZethAddressPriv
    """
    addr_file = get_zeth_address_file(ctx)
    with open(addr_file, "r") as addr_f:
        return ZethAddressPriv.from_json(addr_f.read())


def write_zeth_address_secret(
        secret_addr: ZethAddressPriv, addr_file: str) -> None:
    """
    Write ZethAddressPriv to file
    """
    with open(addr_file, "w") as addr_f:
        addr_f.write(secret_addr.to_json())


def load_zeth_address(ctx: ClientConfig) -> ZethAddress:
    """
    Load a ZethAddress secret from a file, and the associated public address,
    and return as a ZethAddress.
    """
    return ZethAddress.from_secret_public(
        load_zeth_address_secret(ctx),
        load_zeth_address_public(ctx))


def open_wallet(
        mixer_instance: Any,
        js_secret: ZethAddressPriv,
        ctx: ClientConfig) -> Wallet:
    """
    Load a wallet using a secret key.
    """
    wallet_dir = ctx.wallet_dir
    return Wallet(mixer_instance, WALLET_USERNAME, wallet_dir, js_secret)


def do_sync(
        web3: Any,
        wallet: Wallet,
        wait_tx: Optional[str],
        callback: Optional[Callable[[ZethNoteDescription], None]] = None) -> int:
    """
    Implementation of sync, reused by several commands.  Returns the
    block_number synced to.  Also updates and saves the MerkleTree.
    """
    def _do_sync() -> int:
        wallet_next_block = wallet.get_next_block()
        chain_block_number: int = get_block_number(web3)

        if chain_block_number >= wallet_next_block:
            new_merkle_root: Optional[bytes] = None

            print(f"SYNCHING blocks ({wallet_next_block} - {chain_block_number})")
            mixer_instance = wallet.mixer_instance
            for mix_result in get_mix_results(
                    web3, mixer_instance, wallet_next_block, chain_block_number):
                new_merkle_root = mix_result.new_merkle_root
                for note_desc in wallet.receive_notes(mix_result.output_events):
                    if callback:
                        callback(note_desc)

                spent_commits = wallet.mark_nullifiers_used(mix_result.nullifiers)
                for commit in spent_commits:
                    print(f"    SPENT: {commit}")

            wallet.update_and_save_state(next_block=chain_block_number + 1)

            # Check merkle root and save the updated tree
            if new_merkle_root:
                our_merkle_root = wallet.merkle_tree.get_root()
                assert new_merkle_root == our_merkle_root

        return chain_block_number

    # Do a sync upfront (it would be a waste of time to wait for a tx before
    # syncing, as it can take time to traverse all blocks).  Then wait for a tx
    # if requested, and sync again.

    if wait_tx:
        _do_sync()
        tx_receipt = web3.eth.waitForTransactionReceipt(wait_tx, 10000)
        gas_used = tx_receipt.gasUsed
        status = tx_receipt.status
        print(f"{wait_tx[0:8]}: gasUsed={gas_used}, status={status}")

    return _do_sync()


def pub_address_file(addr_file: str) -> str:
    """
    The name of a public address file, given the secret address file.
    """
    return addr_file + ".pub"


def find_pub_address_file(base_file: str) -> str:
    """
    Given a file name, which could point to a private or public key file, guess
    at the name of the public key file.
    """
    pub_addr_file = pub_address_file(base_file)
    if exists(pub_addr_file):
        return pub_addr_file
    if exists(base_file):
        return base_file

    raise ClickException(f"No public key file {pub_addr_file} or {base_file}")


def create_mixer_client(ctx: ClientConfig) -> MixerClient:
    """
    Create a MixerClient for an existing deployment.
    """
    web3 = open_web3_from_ctx(ctx)
    mixer_desc = load_mixer_description_from_ctx(ctx)
    mixer_instance = mixer_desc.mixer.instantiate(web3)
    return MixerClient.open(web3, ctx.prover_server_endpoint, mixer_instance)


def create_zeth_client_and_mixer_desc(
        ctx: ClientConfig) -> Tuple[MixerClient, MixerDescription]:
    """
    Create a MixerClient and MixerDescription object, for an existing deployment.
    """
    web3 = open_web3_from_ctx(ctx)
    mixer_desc = load_mixer_description_from_ctx(ctx)
    mixer_instance = mixer_desc.mixer.instantiate(web3)
    zeth_client = MixerClient.open(
        web3, ctx.prover_server_endpoint, mixer_instance)
    return (zeth_client, mixer_desc)


def zeth_note_short(note_desc: ZethNoteDescription) -> str:
    """
    Generate a short human-readable description of a commitment.
    """
    value = from_zeth_units(int(note_desc.note.value, 16)).ether()
    cm = short_commitment(note_desc.commitment)
    return f"{cm}: value={value} ETH, addr={note_desc.address}"


def zeth_note_short_print(note_desc: ZethNoteDescription) -> None:
    print(f" NEW NOTE: {zeth_note_short(note_desc)}")


def parse_output(output_str: str) -> Tuple[ZethAddressPub, EtherValue]:
    """
    Parse a string of the form "<receiver_pub_key>,<value>" to an output
    specification.
    """
    parts = output_str.split(",")
    if len(parts) != 2:
        raise ClickException(f"invalid output spec: {output_str}")
    return (ZethAddressPub.parse(parts[0]), EtherValue(parts[1]))


def load_eth_address(eth_addr: Optional[str]) -> str:
    """
    Given an --eth-addr command line param, either parse the address, load from
    the file, or use a default file name.
    """
    eth_addr = eth_addr or ETH_ADDRESS_DEFAULT
    if eth_addr.startswith("0x"):
        return Web3.toChecksumAddress(eth_addr)
    if exists(eth_addr):
        with open(eth_addr, "r") as eth_addr_f:
            return Web3.toChecksumAddress(eth_addr_f.read().rstrip())
    raise ClickException(f"could find file or parse eth address: {eth_addr}")
