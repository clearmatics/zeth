#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.cli.constants import \
    PROVER_SERVER_ENDPOINT_DEFAULT, PROVER_CONFIGURATION_FILE_DEFAULT, \
    INSTANCE_FILE_DEFAULT, ZETH_SECRET_ADDRESS_FILE_DEFAULT, WALLET_DIR_DEFAULT, \
    ETH_NETWORK_FILE_DEFAULT, ETH_NETWORK_DEFAULT
from zeth.cli.utils import ClientConfig
from zeth.cli.zeth_get_verification_key import get_verification_key
from zeth.cli.zeth_deploy import deploy
from zeth.cli.zeth_gen_address import gen_address
from zeth.cli.zeth_sync import sync
from zeth.cli.zeth_mix import mix
from zeth.cli.zeth_wait import wait
from zeth.cli.zeth_ls_notes import ls_notes
from zeth.cli.zeth_ls_commits import ls_commits
from click import group, command, option, pass_context, ClickException, Context
from click_default_group import DefaultGroup  # type: ignore
from typing import Optional


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
@option(
    "--prover-server",
    default=PROVER_SERVER_ENDPOINT_DEFAULT,
    help=f"Prover server endpoint (default={PROVER_SERVER_ENDPOINT_DEFAULT})")
@option(
    "--prover-config-file",
    default=PROVER_CONFIGURATION_FILE_DEFAULT,
    help=f"Prover config file (default={PROVER_CONFIGURATION_FILE_DEFAULT})")
@option(
    "--instance-file",
    default=INSTANCE_FILE_DEFAULT,
    help=f"Instance file (default={INSTANCE_FILE_DEFAULT})")
@option(
    "--address-file",
    default=ZETH_SECRET_ADDRESS_FILE_DEFAULT,
    help=f"Zeth zecret address file (default={ZETH_SECRET_ADDRESS_FILE_DEFAULT})")
@option(
    "--wallet-dir",
    default=WALLET_DIR_DEFAULT,
    help=f"Wallet directory (default={WALLET_DIR_DEFAULT})")
@pass_context
def zeth(
        ctx: Context,
        eth_network: Optional[str],
        prover_server: str,
        prover_config_file: str,
        instance_file: str,
        address_file: str,
        wallet_dir: str) -> None:
    if ctx.invoked_subcommand == "help":
        ctx.invoke(help)
    ctx.ensure_object(dict)
    ctx.obj = ClientConfig(
        eth_network=eth_network,
        prover_server_endpoint=prover_server,
        prover_config_file=prover_config_file,
        instance_file=instance_file,
        address_file=address_file,
        wallet_dir=wallet_dir)


zeth.add_command(get_verification_key)
zeth.add_command(deploy)
zeth.add_command(gen_address)
zeth.add_command(sync)
zeth.add_command(mix)
zeth.add_command(wait)
zeth.add_command(ls_notes)
zeth.add_command(ls_commits)
zeth.add_command(help)


if __name__ == "__main__":
    zeth()  # pylint: disable=no-value-for-parameter
