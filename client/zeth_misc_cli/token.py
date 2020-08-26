#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth_misc_cli.token_approve import approve
from zeth_cli.constants import ETH_NETWORK_FILE_DEFAULT, ETH_NETWORK_DEFAULT
from click import group, command, option, pass_context, ClickException, Context
from click_default_group import DefaultGroup


@command()
@pass_context
def help(ctx: Context) -> None:
    """
    Print help and exit
    """
    # Note, this command is implemented to ensure that an error is raised if no
    # subcommand is specified (which also catches errors in scripts).
    print(ctx.parent.get_help())
    raise ClickException("no command specified")


@group(cls=DefaultGroup, default_if_no_args=True, default="help")
@option(
    "--eth-network",
    default=None,
    help="Ethereum RPC endpoint, network or config file "
    f"(default: '{ETH_NETWORK_FILE_DEFAULT}' if it exists, otherwise "
    f"'{ETH_NETWORK_DEFAULT}')")
@pass_context
def token(ctx: Context, eth_network: str) -> None:
    """
    Commands to interact with an ERC20/223 token
    """
    if ctx.invoked_subcommand == "help":
        ctx.invoke(help)
    ctx.ensure_object(dict)
    ctx.obj = {
        "eth_network": eth_network,
    }


token.add_command(approve)
token.add_command(help)


if __name__ == "__main__":
    token()  # pylint: disable=no-value-for-parameter
