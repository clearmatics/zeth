from zeth.utils import EtherValue
from zeth.wallet import Wallet
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
    print(f"Merkle Tree before:\n{mk_tree}")
    deposit_result = zeth_client.deposit(
        mk_tree,
        zeth_address,
        eth_address,
        EtherValue(ether))
    print(f"Merkle Tree after:\n{zeth_client.get_merkle_tree()}")

    wallet = Wallet("local_wallet", ".", zeth_address.addr_sk.k_sk)
    new_notes = wallet.receive_notes(
        deposit_result.encrypted_notes, deposit_result.sender_k_pk)
    print(f"New Notes:\n{new_notes}")
