
def load_instance_id(instance_file: str) -> str:
    """
    Load the mixer instance ID from a file
    """
    with open(instance_file, "r") as instance_f:
        return instance_f.read()


def write_instance_id(instance_id: str, instance_file: str) -> None:
    """
    Write the mixer instance ID to a file
    """
    with open(instance_file, "w") as instance_f:
        instance_f.write(instance_id)
