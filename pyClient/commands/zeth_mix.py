from commands.constants import KEYFILE_DEFAULT
from commands.utils import create_zeth_client, load_zeth_address, \
    open_wallet, parse_output, do_sync, load_eth_address
from zeth.constants import JS_INPUTS, JS_OUTPUTS
from zeth.joinsplit import ZethAddressPub
from zeth.joinsplit import from_zeth_units
from zeth.utils import EtherValue
from api.util_pb2 import ZethNote
from click import command, option, pass_context, ClickException
from typing import List, Tuple, Optional, Any


@command()
@option("--vin", default="0", help="public in value")
@option("--vout", default="0", help="public out value")
@option("--in", "input_notes", multiple=True)
@option("--out", "output_specs", multiple=True, help="<receiver_pub_key>,<value>")
@option("--key-file", default=KEYFILE_DEFAULT)
@option("--eth-addr", help="Sender eth address or address filename")
@option("--wait", is_flag=True)
@pass_context
def mix(
        ctx: Any,
        vin: str,
        vout: str,
        input_notes: List[str],
        output_specs: List[str],
        key_file: str,
        eth_addr: Optional[str],
        wait: bool) -> None:
    """
    Generic mix function
    """

    # Some sanity checks
    if len(input_notes) > JS_INPUTS:
        raise ClickException(f"too many inputs (max {JS_INPUTS})")
    if len(output_specs) > JS_OUTPUTS:
        raise ClickException(f"too many outputs (max {JS_OUTPUTS})")

    print(f"vin = {vin}")
    print(f"vout = {vout}")

    vin_pub = EtherValue(vin)
    vout_pub = EtherValue(vout)
    zeth_client = create_zeth_client(ctx)
    zeth_address = load_zeth_address(ctx)
    wallet = open_wallet(zeth_client.mixer_instance, zeth_address.addr_sk, ctx)

    inputs: List[Tuple[int, ZethNote]] = [
        wallet.find_note(note_id).as_input() for note_id in input_notes]
    outputs: List[Tuple[ZethAddressPub, EtherValue]] = [
        parse_output(out_spec) for out_spec in output_specs]

    # Compute input and output value total and check that they match
    input_note_sum = from_zeth_units(
        sum([int(note.value, 16) for _, note in inputs]))
    output_note_sum = sum([value for _, value in outputs], EtherValue(0))
    if vin_pub + input_note_sum != vout_pub + output_note_sum:
        raise ClickException("input and output value mismatch")

    eth_address = load_eth_address(eth_addr)

    mk_tree = zeth_client.get_merkle_tree()
    tx_hash = zeth_client.joinsplit(
        mk_tree,
        zeth_address.ownership_keypair(),
        eth_address,
        inputs,
        outputs,
        vin_pub,
        vout_pub)

    if wait:
        do_sync(zeth_client.web3, wallet, tx_hash)
    else:
        print(tx_hash)
