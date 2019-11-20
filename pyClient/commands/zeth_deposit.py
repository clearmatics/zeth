from commands.constants import ZETH_KEYFILE_DEFAULT
from click import command, argument, option
from typing import Any


@command()
@argument("eth-address")
@argument("ether")
@option("key-file", default=ZETH_KEYFILE_DEFAULT)
def deposit(ctx: Any, eth_address: str, ether: str) -> None:
    """
    Deposit <ether> ETH as a new Zeth note
    """
    print(f"deposit: host={ctx.obj['HOST']}")
    print(f"deposit: eth_address={eth_address}")
    print(f"deposit: ether={ether}")
