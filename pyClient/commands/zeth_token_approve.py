# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from commands.utils import load_eth_address, open_web3_from_ctx, \
    load_mixer_description_from_ctx, EtherValue
from click import command, argument, option, pass_context, ClickException, Context


@command(name="token-approve")
@argument("tokens")
@option("--eth-addr", help="Sender eth address or address filename")
@option("--wait", is_flag=True, help="Wait for transaction to complete")
@pass_context
def token_approve(ctx: Context, tokens: str, eth_addr: str, wait: bool) -> None:
    """
    Approve the mixer to spend some amount of tokens
    """
    approve_value = EtherValue(tokens)
    eth_addr = load_eth_address(eth_addr)
    web3 = open_web3_from_ctx(ctx)
    mixer_desc = load_mixer_description_from_ctx(ctx)
    if not mixer_desc.token:
        raise ClickException("no token for mixer {mixer_desc.mixer.address}")

    token_instance = mixer_desc.token.instantiate(web3)
    tx_hash = token_instance.functions.approve(
        mixer_desc.mixer.address,
        approve_value.wei).transact({'from': eth_addr})

    if wait:
        web3.eth.waitForTransactionReceipt(tx_hash)  # pylint: disable=no-member
    else:
        print(tx_hash.hex())
