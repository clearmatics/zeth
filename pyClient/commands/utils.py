from zeth.contracts import \
    InstanceDescription, contract_instance, contract_description
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
