# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.cli.utils import create_mixer_client_and_mixer_desc, \
    load_zeth_address, open_wallet, parse_output, do_sync, load_eth_address, \
    load_eth_private_key, zeth_note_short_print, create_prover_client
from zeth.core.constants import JS_INPUTS, JS_OUTPUTS
from zeth.core.mixer_client import ZethAddressPub
from zeth.core.utils import EtherValue, from_zeth_units
from zeth.api.zeth_messages_pb2 import ZethNote
from click import command, option, pass_context, ClickException, Context
from typing import List, Tuple, Optional
import json


@command()
@option("--vin", default="0", help="Public input value")
@option("--vout", default="0", help="Public output value")
@option("--in", "input_notes", multiple=True, help="Input note identifier")
@option(
    "--out",
    "output_specs",
    multiple=True,
    help="<receiver_pub_addr>,<value> where <receiver_pub_addr> can be a "
    "filename or hex address")
@option("--eth-addr", help="Sender's eth address or address filename")
@option("--eth-private-key", help="Sender's eth private key file")
@option("--wait", is_flag=True, help="Wait for transaction to be mined")
@option(
    "--for-dispatch-call",
    is_flag=True,
    help="Generate signature for later call to dispatch (implies --dry-run)")
@option("--dump-parameters", help="Write mix parameters to file ('-' for stdout)")
@option("--dry-run", "-n", is_flag=True, help="Do not send the mix transaction")
@pass_context
def mix(
        ctx: Context,
        vin: str,
        vout: str,
        input_notes: List[str],
        output_specs: List[str],
        eth_addr: Optional[str],
        eth_private_key: Optional[str],
        wait: bool,
        for_dispatch_call: bool,
        dump_parameters: Optional[str],
        dry_run: bool) -> None:
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
    prover_client = create_prover_client(client_ctx)
    zeth_client, mixer_desc = create_mixer_client_and_mixer_desc(
        client_ctx, prover_client)
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
    eth_private_key_data = load_eth_private_key(eth_private_key)

    # If instance uses an ERC20 token, tx_value can be 0. Otherwise it should
    # match vin_pub.
    tx_value = EtherValue(0) if mixer_desc.token else vin_pub

    # Create the MixParameters object manually so they can be displayed.
    # TODO: support saving the generated MixParameters to be sent later.
    mix_params, _ = zeth_client.create_mix_parameters_and_signing_key(
        prover_client,
        wallet.merkle_tree,
        zeth_address.ownership_keypair(),
        eth_address,
        inputs,
        outputs,
        vin_pub,
        vout_pub,
        for_dispatch_call=for_dispatch_call)

    # Dump parameters if requested
    if dump_parameters:
        if dump_parameters == '-':
            print(f"mix_params={mix_params.to_json()}")
        else:
            with open(dump_parameters, "w") as mix_params_f:
                json.dump(mix_params.to_json_dict(), mix_params_f)

    # Early-out if dry_run flag is set
    if for_dispatch_call or dry_run:
        return

    tx_hash = zeth_client.mix(
        mix_params=mix_params,
        sender_eth_address=eth_address,
        sender_eth_private_key=eth_private_key_data,
        tx_value=tx_value)

    print(tx_hash)
    if wait:
        pp = prover_client.get_configuration().pairing_parameters
        do_sync(zeth_client.web3, wallet, pp, tx_hash, zeth_note_short_print)
