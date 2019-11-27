from zeth.utils import EtherValue
from commands.utils import load_zeth_address, create_zeth_client, do_sync
from commands.constants import KEYFILE_DEFAULT, WALLET_DIR_DEFAULT
from click import command, argument, option, pass_context
from typing import Any


@command()
@argument("eth-address")
@argument("ether")
@option("--key-file", default=KEYFILE_DEFAULT)
@option("--wallet-dir", default=WALLET_DIR_DEFAULT)
@option("--wait", is_flag=True, help="Wait for transaction to complete")
@pass_context
def deposit(
        ctx: Any,
        eth_address: str,
        ether: str,
        key_file: str,
        wallet_dir: str,
        wait: bool) -> None:
    """
    Deposit <ether> ETH from <eth-address> as a new Zeth note.
    """
    zeth_address = load_zeth_address(key_file)
    zeth_client = create_zeth_client(ctx)
    mk_tree = zeth_client.get_merkle_tree()
    tx_hash = zeth_client.deposit(
        mk_tree,
        zeth_address,
        eth_address,
        EtherValue(ether))

    if wait:
        do_sync(
            zeth_client.mixer_instance,
            zeth_address.addr_sk,
            wallet_dir,
            tx_hash)
    else:
        print(tx_hash)
