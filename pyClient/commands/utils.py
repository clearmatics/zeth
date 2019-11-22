from zeth.contracts import \
    InstanceDescription, contract_instance, contract_description
from zeth.joinsplit import JoinsplitPublicKey, JoinsplitSecretKey
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


def load_joinsplit_public_key(key_file: str) -> JoinsplitPublicKey:
    """
    Load a JoinsplitPublicKey from a key file.
    """
    with open(key_file, "r") as pub_key_f:
        return JoinsplitPublicKey.parse(pub_key_f.read())


def write_joinsplit_public_key(
        pub_key: JoinsplitPublicKey, key_file: str) -> None:
    """
    Write a JoinsplitPublicKey to a file
    """
    with open(key_file, "w") as pub_key_f:
        pub_key_f.write(str(pub_key))


def load_joinsplit_secret_key(key_file: str) -> JoinsplitSecretKey:
    """
    Read JoinsplitSecretKey
    """
    with open(key_file, "r") as key_f:
        return JoinsplitSecretKey.from_json(key_f.read())


def write_joinsplit_secret_key(
        secret_key: JoinsplitSecretKey, key_file: str) -> None:
    """
    Write JoinsplitSecretKey to file
    """
    with open(key_file, "w") as key_f:
        key_f.write(secret_key.to_json())


def pub_key_file_name(key_file: str) -> str:
    """
    Ther name of a public key file, given the secret key file.
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
