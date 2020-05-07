# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from commands.utils import create_zeth_client_and_mixer_desc, \
    load_zeth_address, open_wallet, parse_output, do_sync, load_eth_address
from zeth.constants import JS_INPUTS, JS_OUTPUTS
from zeth.mixer_client import ZethAddressPub
from zeth.utils import EtherValue, from_zeth_units
from api.zeth_messages_pb2 import ZethNote
from click import command, option, pass_context, ClickException, Context
from typing import List, Tuple, Optional


@command()
@option("--vin", default="0", help="public in value")
@option("--vout", default="0", help="public out value")
@option("--in", "input_notes", multiple=True)
@option("--out", "output_specs", multiple=True, help="<receiver_pub_key>,<value>")
@option("--eth-addr", help="Sender eth address or address filename")
@option("--wait", is_flag=True)
@pass_context
def mix(
        ctx: Context,
        vin: str,
        vout: str,
        input_notes: List[str],
        output_specs: List[str],
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
    client_ctx = ctx.obj
    zeth_client, mixer_desc = create_zeth_client_and_mixer_desc(client_ctx)
    zeth_address = load_zeth_address(client_ctx)
    wallet = open_wallet(
        zeth_client.mixer_instance, zeth_address.addr_sk, client_ctx)

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

    # If instance uses an ERC20 token, tx_value can be 0 not default vin_pub.
    tx_value: Optional[EtherValue] = None
    if mixer_desc.token:
        tx_value = EtherValue(0)

    tx_hash = zeth_client.joinsplit(
        wallet.merkle_tree,
        zeth_address.ownership_keypair(),
        eth_address,
        inputs,
        outputs,
        vin_pub,
        vout_pub,
        tx_value)

    if wait:
        do_sync(zeth_client.web3, wallet, tx_hash)
    else:
        print(tx_hash)
