# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from commands.constants import INSTANCE_FILE_DEFAULT
from commands.utils import \
    open_web3_from_ctx, get_erc20_instance_description, load_eth_address, \
    write_mixer_description, MixerDescription
from zeth.mixer_client import MixerClient
from zeth.utils import EtherValue
from click import Context, command, option, pass_context
from typing import Optional


@command()
@option("--eth-addr", help="Sender eth address or address filename")
@option(
    "--instance-out",
    default=INSTANCE_FILE_DEFAULT,
    help=f"File to write deployment address to (default={INSTANCE_FILE_DEFAULT})")
@option("--token-address", help="Address of token contract (if used)")
@option("--deploy-gas", help="Maximum gas, in Wei")
@pass_context
def deploy(
        ctx: Context,
        eth_addr: Optional[str],
        instance_out: str,
        token_address: str,
        deploy_gas: str) -> None:
    """
    Deploy the zeth contracts and record the instantiation details.
    """
    eth_address = load_eth_address(eth_addr)
    client_ctx = ctx.obj
    web3 = open_web3_from_ctx(client_ctx)
    deploy_gas_value = EtherValue(deploy_gas, 'wei') if deploy_gas else None

    print(f"deploy: eth_address={eth_address}")
    print(f"deploy: instance_out={instance_out}")
    print(f"deploy: token_address={token_address}")

    token_instance_desc = get_erc20_instance_description(token_address) \
        if token_address else None

    _zeth_client, mixer_instance_desc = MixerClient.deploy(
        web3,
        client_ctx.prover_server_endpoint,
        eth_address,
        token_address,
        deploy_gas_value)

    mixer_desc = MixerDescription(mixer_instance_desc, token_instance_desc)
    write_mixer_description(instance_out, mixer_desc)
