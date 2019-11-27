from zeth.utils import EtherValue
from commands.utils import load_zeth_address, create_zeth_client
from commands.constants import KEYFILE_DEFAULT
from click import command, argument, option, pass_context
from typing import Any


@command()
@argument("eth-address")
@argument("ether")
@option("--key-file", default=KEYFILE_DEFAULT)
@pass_context
def deposit(ctx: Any, eth_address: str, ether: str, key_file: str) -> None:
    """
    Deposit <ether> ETH from <eth-address> as a new Zeth note.
    """
    zeth_address = load_zeth_address(key_file)
    zeth_client = create_zeth_client(ctx)
    mk_tree = zeth_client.get_merkle_tree()
    zeth_client.deposit(
        mk_tree,
        zeth_address,
        eth_address,
        EtherValue(ether))
    print("Deposit transaction sent")
