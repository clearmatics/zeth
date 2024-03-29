#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.helper.eth_gen_network_config import eth_gen_network_config
from zeth.helper.eth_gen_address import eth_gen_address
from zeth.helper.eth_get_balance import eth_get_balance
from zeth.helper.eth_fund import eth_fund
from zeth.helper.eth_send import eth_send
from zeth.helper.eth_get_contract_address import eth_get_contract_address
from zeth.helper.token_approve import token_approve
from zeth.cli.constants import ETH_NETWORK_FILE_DEFAULT, ETH_NETWORK_DEFAULT
from click import group, command, option, pass_context, ClickException, Context
from click_default_group import DefaultGroup  # type: ignore


# pylint: disable=redefined-builtin
@command()
@pass_context
def help(ctx: Context) -> None:
    """
    Print help and exit
    """
    # Note, this command is implemented to ensure that an error is raised if no
    # subcommand is specified (which also catches errors in scripts).
    print(ctx.parent.get_help())  # type: ignore
    raise ClickException("no command specified")


@group(cls=DefaultGroup, default_if_no_args=True, default="help")
@option(
    "--eth-network",
    default=None,
    help="Ethereum RPC endpoint, network or config file "
    f"(default: '{ETH_NETWORK_FILE_DEFAULT}' if it exists, otherwise "
    f"'{ETH_NETWORK_DEFAULT}')")
@pass_context
def zeth_helper(ctx: Context, eth_network: str) -> None:
    if ctx.invoked_subcommand == "help":
        ctx.invoke(help)
    ctx.ensure_object(dict)
    ctx.obj = {
        "eth_network": eth_network,
    }


zeth_helper.add_command(eth_gen_network_config)
zeth_helper.add_command(eth_gen_address)
zeth_helper.add_command(eth_get_balance)
zeth_helper.add_command(eth_fund)
zeth_helper.add_command(eth_send)
zeth_helper.add_command(eth_get_contract_address)
zeth_helper.add_command(token_approve)
zeth_helper.add_command(help)


if __name__ == "__main__":
    zeth_helper()  # pylint: disable=no-value-for-parameter
