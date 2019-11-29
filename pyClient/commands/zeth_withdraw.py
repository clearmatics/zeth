from commands.utils import load_eth_address, create_zeth_client, \
    load_joinsplit_keypair, open_wallet, do_sync
from zeth.constants import JS_INPUTS
from zeth.joinsplit import from_zeth_units
from zeth.utils import EtherValue
from click import command, option, pass_context, ClickException
from typing import List, Any


@command()
@option("--in", "input_notes", multiple=True)
@option("--eth-addr", help="Sender eth address or address filename")
@option("--wait", is_flag=True, help="Wait for transaction to complete")
@pass_context
def withdraw(ctx: Any, input_notes: List[str], eth_addr: str, wait: bool) -> None:
    """
    Withdraw notes to eth_addr
    """
    # Some sanity checks
    if len(input_notes) == 0:
        raise ClickException(f"no inputs specified")
    if len(input_notes) > JS_INPUTS:
        raise ClickException(f"too many inputs (max {JS_INPUTS})")

    eth_address = load_eth_address(eth_addr)
    zeth_client = create_zeth_client(ctx)
    js_keypair = load_joinsplit_keypair(ctx)
    wallet = open_wallet(zeth_client.mixer_instance, js_keypair.addr_sk, ctx)

    inputs = [wallet.find_note(note_id).as_input() for note_id in input_notes]
    input_sum = from_zeth_units(sum([int(note.value, 16) for _, note in inputs]))

    mk_tree = zeth_client.get_merkle_tree()
    tx_hash = zeth_client.joinsplit(
        mk_tree,
        js_keypair.ownership_keypair(),
        eth_address,
        inputs,
        [],
        EtherValue(0),
        input_sum,
        EtherValue(0))

    if wait:
        do_sync(zeth_client.web3, wallet, tx_hash)
    else:
        print(tx_hash)
