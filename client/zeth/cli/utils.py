# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.cli.constants import WALLET_USERNAME, ETH_ADDRESS_DEFAULT, \
    ETH_PRIVATE_KEY_FILE_DEFAULT, ETH_RPC_ENDPOINT_DEFAULTS, \
    ETH_NETWORK_FILE_DEFAULT, ETH_NETWORK_DEFAULT, \
    ZETH_PUBLIC_ADDRESS_FILE_DEFAULT
from zeth.core.zeth_address import ZethAddressPub, ZethAddressPriv, ZethAddress
from zeth.core.contracts import \
    InstanceDescription, get_block_number, get_mix_results, compile_files
from zeth.core.prover_client import ProverClient
from zeth.core.mixer_client import MixerClient
from zeth.core.utils import \
    open_web3, short_commitment, EtherValue, get_zeth_dir, from_zeth_units
from zeth.core.wallet import ZethNoteDescription, Wallet
from click import ClickException
import json
from os.path import exists, join, splitext
from web3 import Web3  # type: ignore
from typing import Dict, Tuple, Optional, Callable, Any


class NetworkConfig:
    """
    Simple description of a network. Name (may be used in some cases to
    understand the type of network) and endpoint URL.
    """
    def __init__(
            self,
            name: str,
            endpoint: str,
            certificate: Optional[str] = None,
            insecure: bool = False):
        self.name = name
        self.endpoint = endpoint
        self.certificate = certificate
        self.insecure = insecure

    def to_json(self) -> str:
        json_dict: Dict[str, Any] = {
            "name": self.name,
            "endpoint": self.endpoint,
        }
        if self.certificate:
            json_dict["certificate"] = self.certificate
        if self.insecure:
            json_dict["insecure"] = self.insecure
        return json.dumps(json_dict)

    @staticmethod
    def from_json(network_config_json: str) -> NetworkConfig:
        json_dict = json.loads(network_config_json)
        return NetworkConfig(
            name=json_dict["name"],
            endpoint=json_dict["endpoint"],
            certificate=json_dict.get("certificate", None),
            insecure=json_dict.get("insecure", None))


class ClientConfig:
    """
    Context for users of these client tools
    """
    def __init__(
            self,
            eth_network: Optional[str],
            prover_server_endpoint: str,
            prover_config_file: str,
            instance_file: str,
            address_file: str,
            wallet_dir: str):
        self.eth_network = eth_network
        self.prover_server_endpoint = prover_server_endpoint
        self.prover_config_file = prover_config_file
        self.instance_file = instance_file
        self.address_file = address_file
        self.wallet_dir = wallet_dir


def get_eth_network(eth_network: Optional[str]) -> NetworkConfig:
    """
    Parse the `eth_network` parameter to extract a URL. If `eth_network` does
    not contain a URL, try interpreting it as a network name, otherwise
    interpret it as a file to load the network config from. Fall back to a
    default network config filename, and finally the default network name.
    """
    if eth_network is None:
        if exists(ETH_NETWORK_FILE_DEFAULT):
            eth_network = ETH_NETWORK_FILE_DEFAULT
        else:
            eth_network = ETH_NETWORK_DEFAULT

    if eth_network.startswith("http"):
        # When given only a url, assume the default network name
        return NetworkConfig(ETH_NETWORK_DEFAULT, eth_network)

    # Try loading from a file
    if exists(eth_network):
        with open(eth_network) as network_f:
            return NetworkConfig.from_json(network_f.read())

    # Assume a network name
    try:
        endpoint = ETH_RPC_ENDPOINT_DEFAULTS[eth_network]
        return NetworkConfig(eth_network, endpoint)
    except KeyError:
        raise ClickException(f"invalid network name / url: {eth_network}")


def open_web3_from_network(eth_net: NetworkConfig) -> Any:
    return open_web3(
        url=eth_net.endpoint,
        certificate=eth_net.certificate,
        insecure=eth_net.insecure)


def open_web3_from_ctx(ctx: ClientConfig) -> Any:
    eth_net = get_eth_network(ctx.eth_network)
    return open_web3_from_network(eth_net)


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
        callback: Optional[Callable[[ZethNoteDescription], None]] = None,
        batch_size: Optional[int] = None) -> int:
    """
    Implementation of sync, reused by several commands.  Returns the
    block_number synced to.  Also updates and saves the MerkleTree.
    """
    def _do_sync() -> int:
        wallet_next_block = wallet.get_next_block()
        chain_block_number = get_block_number(web3)

        if chain_block_number >= wallet_next_block:
            new_merkle_root: Optional[bytes] = None

            print(f"SYNCHING blocks ({wallet_next_block} - {chain_block_number})")
            mixer_instance = wallet.mixer_instance
            for mix_result in get_mix_results(
                    web3,
                    mixer_instance,
                    wallet_next_block,
                    chain_block_number,
                    batch_size):
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
    return splitext(addr_file)[0] + ".pub"


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


def create_prover_client(ctx: ClientConfig) -> ProverClient:
    """
    Create a prover client using the settings from the commands context.
    """
    return ProverClient(
        ctx.prover_server_endpoint, ctx.prover_config_file)


def create_mixer_client(ctx: ClientConfig) -> MixerClient:
    """
    Create a MixerClient for an existing deployment.
    """
    web3 = open_web3_from_ctx(ctx)
    mixer_desc = load_mixer_description_from_ctx(ctx)
    mixer_instance = mixer_desc.mixer.instantiate(web3)
    prover_client = create_prover_client(ctx)
    return MixerClient(web3, prover_client, mixer_instance)


def create_zeth_client_and_mixer_desc(
        ctx: ClientConfig) -> Tuple[MixerClient, MixerDescription]:
    """
    Create a MixerClient and MixerDescription object, for an existing deployment.
    """
    web3 = open_web3_from_ctx(ctx)
    mixer_desc = load_mixer_description_from_ctx(ctx)
    mixer_instance = mixer_desc.mixer.instantiate(web3)
    prover_client = create_prover_client(ctx)
    zeth_client = MixerClient(web3, prover_client, mixer_instance)
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
    Parse a string of the form "<receiver_pub_address>,<value>" to an output
    specification. <receiver_pub_address> can be a file name containing the
    address. "<value>" is interpretted as the <default-address-file>,<value>.
    """
    parts = output_str.split(",")
    if len(parts) == 1:
        addr = ZETH_PUBLIC_ADDRESS_FILE_DEFAULT
        value = parts[0]
    elif len(parts) == 2:
        addr = parts[0]
        value = parts[1]
    else:
        raise ClickException(f"invalid output spec: {output_str}")

    if exists(addr):
        with open(addr, "r") as addr_f:
            addr = addr_f.read()

    return (ZethAddressPub.parse(addr), EtherValue(value))


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


def write_eth_address(eth_addr: str, eth_addr_file: str) -> None:
    if exists(eth_addr_file):
        raise ClickException(f"refusing to overwrite address \"{eth_addr_file}\"")
    with open(eth_addr_file, "w") as eth_addr_f:
        eth_addr_f.write(eth_addr)


def load_eth_private_key(private_key_file: Optional[str]) -> Optional[bytes]:
    private_key_file = private_key_file or ETH_PRIVATE_KEY_FILE_DEFAULT
    if exists(private_key_file):
        with open(private_key_file, "rb") as private_key_f:
            return private_key_f.read(32)
    return None


def write_eth_private_key(private_key: bytes, private_key_file: str) -> None:
    if exists(private_key_file):
        raise ClickException(
            f"refusing to overwrite private key \"{private_key_file}\"")
    with open(private_key_file, "wb") as private_key_f:
        private_key_f.write(private_key)
