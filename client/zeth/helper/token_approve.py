# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.cli.constants import INSTANCE_FILE_DEFAULT
from zeth.cli.utils import load_eth_address, load_eth_private_key, \
    get_eth_network, open_web3_from_network, load_mixer_description, EtherValue
from zeth.core.contracts import send_contract_call
from click import command, argument, option, pass_context, ClickException, Context


@command()
@argument("value")
@option("--eth-addr", help="Sender eth address or address filename")
@option("--eth-private-key", help="Sender eth private key")
@option("--wait", is_flag=True, help="Wait for transaction to complete")
@option(
    "--instance-file",
    default=INSTANCE_FILE_DEFAULT,
    help=f"Instance file (default={INSTANCE_FILE_DEFAULT})")
@pass_context
def token_approve(
        ctx: Context,
        value: str,
        eth_addr: str,
        eth_private_key: str,
        wait: bool,
        instance_file: str) -> None:
    """
    Approve the mixer to spend some amount of ERC20/223 tokens
    """
    approve_value = EtherValue(value)
    eth_addr = load_eth_address(eth_addr)
    eth_private_key_data = load_eth_private_key(eth_private_key)
    web3 = open_web3_from_network(get_eth_network(ctx.obj["eth_network"]))
    mixer_desc = load_mixer_description(instance_file)
    if not mixer_desc.token:
        raise ClickException("no token for mixer {mixer_desc.mixer.address}")

    token_instance = mixer_desc.token.instantiate(web3)
    approve_call = token_instance.functions.approve(
        mixer_desc.mixer.address,
        approve_value.wei)
    tx_hash = send_contract_call(
        web3, approve_call, eth_addr, eth_private_key_data)

    if wait:
        web3.eth.waitForTransactionReceipt(tx_hash)  # pylint: disable=no-member
    else:
        print(tx_hash.hex())
