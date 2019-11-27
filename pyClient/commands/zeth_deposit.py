from zeth.utils import EtherValue
from commands.utils import \
    load_zeth_address, create_zeth_client, open_wallet, do_sync
from click import command, argument, option, pass_context
from typing import Any


@command()
@argument("eth-address")
@argument("ether")
@option("--wait", is_flag=True, help="Wait for transaction to complete")
@pass_context
def deposit(
        ctx: Any,
        eth_address: str,
        ether: str,
        wait: bool) -> None:
    """
    Deposit <ether> ETH from <eth-address> as a new Zeth note.
    """
    zeth_address = load_zeth_address(ctx)
    zeth_client = create_zeth_client(ctx)
    mk_tree = zeth_client.get_merkle_tree()
    tx_hash = zeth_client.deposit(
        mk_tree,
        zeth_address,
        eth_address,
        EtherValue(ether))

    if wait:
        wallet = open_wallet(
            zeth_client.mixer_instance,
            zeth_address.addr_sk,
            ctx)
        do_sync(zeth_address.addr_sk, wallet, tx_hash)
    else:
        print(tx_hash)
