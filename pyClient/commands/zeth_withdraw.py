from commands.constants import ZETH_KEYFILE_DEFAULT
from click import command, option
from typing import List, Any


@command()
@option("--in", multiple=True, target="inputs")
@option("--eth-address")
@option("--key-file", default=ZETH_KEYFILE_DEFAULT)
def withdraw(
        ctx: Any,
        inputs: List[str],
        eth_address: str,
        key_file: str) -> None:
    """
    Send notes to zethAddresses
    """
    print(f"withdraw: host={ctx.obj['HOST']}")
    print(f"withdraw: inputs={inputs}")
    print(f"withdraw: eth_address={eth_address}")
    print(f"withdraw: key_file={key_file}")
