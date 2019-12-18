# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from commands.constants import WALLET_USERNAME, ETH_ADDRESS_DEFAULT
from zeth.constants import ZETH_MERKLE_TREE_DEPTH
from zeth.contracts import InstanceDescription, get_block_number, get_mix_results
from zeth.joinsplit import \
    ZethAddressPub, ZethAddressPriv, ZethAddress, ZethClient, from_zeth_units
from zeth.utils import open_web3, short_commitment, EtherValue, get_zeth_dir
from zeth.wallet import ZethNoteDescription, Wallet
from click import ClickException, Context
import json
from os.path import exists, join
from solcx import compile_files  # type: ignore
from typing import Dict, Tuple, Optional, Any


def open_web3_from_ctx(ctx: Context) -> Any:
    return open_web3(ctx.obj["ETH_RPC"])


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
        zeth_dir, "zeth-contracts", "node_modules", "openzeppelin-solidity")
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


def load_mixer_description_from_ctx(ctx: Any) -> MixerDescription:
    return load_mixer_description(ctx.obj["INSTANCE_FILE"])


def get_zeth_address_file(ctx: Context) -> str:
    return ctx.obj["ADDRESS_FILE"]


def load_zeth_address_public(ctx: Context) -> ZethAddressPub:
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


def load_zeth_address_secret(ctx: Context) -> ZethAddressPriv:
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


def load_zeth_address(ctx: Context) -> ZethAddress:
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
        ctx: Context) -> Wallet:
    """
    Load a wallet using a secret key.
    """
    wallet_dir = ctx.obj["WALLET_DIR"]
    return Wallet(mixer_instance, WALLET_USERNAME, wallet_dir, js_secret.k_sk)


def do_sync(
        web3: Any,
        wallet: Wallet,
        wait_tx: Optional[str]) -> int:
    """
    Implementation of sync, reused by several commands.  Returns the
    block_number synced to.
    """
    def _do_sync() -> int:
        wallet_next_block = wallet.get_next_block()
        chain_block_number: int = get_block_number(web3)

        if chain_block_number >= wallet_next_block:
            print(f"SYNCHING blocks ({wallet_next_block} - {chain_block_number})")
            mixer_instance = wallet.mixer_instance
            for mix_result in get_mix_results(
                    web3, mixer_instance, wallet_next_block, chain_block_number):
                for note_desc in wallet.receive_notes(
                        mix_result.encrypted_notes, mix_result.sender_k_pk):
                    print(f" NEW NOTE: {zeth_note_short(note_desc)}")
            wallet.set_next_block(chain_block_number + 1)
        return chain_block_number

    # Do a sync upfront (it would be a waste of time to wait for a tx before
    # syncing, as it can take time to traverse all blocks).  Then wait for a tx
    # if requested, and sync again.

    if wait_tx:
        _do_sync()
        web3.eth.waitForTransactionReceipt(wait_tx, 10000)
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


def create_zeth_client(ctx: Context) -> ZethClient:
    """
    Create a ZethClient for an existing deployment.
    """
    web3 = open_web3_from_ctx(ctx)
    mixer_desc = load_mixer_description_from_ctx(ctx)
    mixer_instance = mixer_desc.mixer.instantiate(web3)
    prover_client = ctx.obj["PROVER_CLIENT"]
    zksnark = ctx.obj["ZKSNARK"]
    return ZethClient.open(
        web3, prover_client, ZETH_MERKLE_TREE_DEPTH, mixer_instance, zksnark)


def create_zeth_client_and_mixer_desc(
        ctx: Context) -> Tuple[ZethClient, MixerDescription]:
    """
    Create a ZethClient and MixerDescription object, for an existing deployment.
    """
    web3 = open_web3_from_ctx(ctx)
    mixer_desc = load_mixer_description_from_ctx(ctx)
    mixer_instance = mixer_desc.mixer.instantiate(web3)
    prover_client = ctx.obj["PROVER_CLIENT"]
    zksnark = ctx.obj["ZKSNARK"]
    zeth_client = ZethClient.open(
        web3, prover_client, ZETH_MERKLE_TREE_DEPTH, mixer_instance, zksnark)
    return (zeth_client, mixer_desc)


def zeth_note_short(note_desc: ZethNoteDescription) -> str:
    """
    Generate a short human-readable description of a commitment.
    """
    value = from_zeth_units(int(note_desc.note.value, 16)).ether()
    cm = short_commitment(note_desc.commitment)
    return f"{cm}: value={value} ETH, addr={note_desc.address}"


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
        return eth_addr
    if exists(eth_addr):
        with open(eth_addr, "r") as eth_addr_f:
            return eth_addr_f.read().rstrip()
    raise ClickException(f"could find file or parse eth address: {eth_addr}")
