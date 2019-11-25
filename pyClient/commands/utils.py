from commands.constants import WALLET_USERNAME
from zeth.constants import ZETH_MERKLE_TREE_DEPTH
from zeth.contracts import \
    InstanceDescription, contract_instance, contract_description
from zeth.joinsplit import \
    ZethAddressPub, ZethAddressPriv, ZethAddress, ZethClient
from zeth.wallet import Wallet
from click import ClickException
from os.path import exists
from typing import Any


def load_zeth_instance(instance_file: str) -> Any:
    """
    Load the mixer instance ID from a file
    """
    with open(instance_file, "r") as instance_f:
        instance_desc = InstanceDescription.from_json(instance_f.read())
    return contract_instance(instance_desc)


def write_zeth_instance(zeth_instance: Any, instance_file: str) -> None:
    """
    Write the mixer instance ID to a file
    """
    with open(instance_file, "w") as instance_f:
        instance_f.write(contract_description(zeth_instance).to_json())


def load_zeth_address_public(key_file: str) -> ZethAddressPub:
    """
    Load a ZethAddressPub from a key file.
    """
    with open(key_file, "r") as pub_key_f:
        return ZethAddressPub.parse(pub_key_f.read())


def write_zeth_address_public(
        pub_key: ZethAddressPub, key_file: str) -> None:
    """
    Write a ZethAddressPub to a file
    """
    with open(key_file, "w") as pub_key_f:
        pub_key_f.write(str(pub_key))


def load_zeth_address_secret(key_file: str) -> ZethAddressPriv:
    """
    Read ZethAddressPriv
    """
    with open(key_file, "r") as key_f:
        return ZethAddressPriv.from_json(key_f.read())


def write_zeth_address_secret(
        secret_key: ZethAddressPriv, key_file: str) -> None:
    """
    Write ZethAddressPriv to file
    """
    with open(key_file, "w") as key_f:
        key_f.write(secret_key.to_json())


def load_zeth_address(secret_key_file: str) -> ZethAddress:
    """
    Load a joinsplit secret key from a file, and the associated public key, as a
    ZethAddress.
    """
    return ZethAddress.from_secret_public(
        load_zeth_address_secret(secret_key_file),
        load_zeth_address_public(pub_key_file_name(secret_key_file)))


def open_wallet(secret_key_file: str, wallet_dir: str) -> Wallet:
    """
    Load a wallet using a secret key.
    """
    js_secret = load_zeth_address_secret(secret_key_file)
    return Wallet(WALLET_USERNAME, wallet_dir, js_secret.k_sk)


def pub_key_file_name(key_file: str) -> str:
    """
    The name of a public key file, given the secret key file.
    """
    return key_file + ".pub"


def find_pub_key_file(base_file: str) -> str:
    """
    Given a file name, which could point to a private or public key file, guess
    at the name of the public key file.
    """
    pub_key_file = pub_key_file_name(base_file)
    if exists(pub_key_file):
        return pub_key_file
    if exists(base_file):
        return base_file

    raise ClickException(f"No public key file {pub_key_file} or {base_file}")


def create_zeth_client(ctx: Any) -> ZethClient:
    """
    Create a ZethClient for an existing deployment, given all appropriate
    information.
    """
    mixer_instance = load_zeth_instance(ctx.obj["INSTANCE_FILE"])
    prover_client = ctx.obj["PROVER_CLIENT"]
    zksnark = ctx.obj["ZKSNARK"]
    return ZethClient.open(
        prover_client,
        ZETH_MERKLE_TREE_DEPTH,
        mixer_instance,
        zksnark)
