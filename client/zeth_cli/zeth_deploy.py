# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth_cli.constants import INSTANCE_FILE_DEFAULT
from zeth_cli.utils import \
    open_web3_from_ctx, get_erc20_instance_description, load_eth_address, \
    load_eth_private_key, write_mixer_description, MixerDescription
from core.mixer_client import MixerClient
from core.utils import EtherValue
from click import Context, command, option, pass_context
from typing import Optional


@command()
@option("--eth-addr", help="Sender eth address or address filename")
@option("--eth-private-key", help="Sender's eth private key file")
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
        eth_private_key: Optional[str],
        instance_out: str,
        token_address: str,
        deploy_gas: str) -> None:
    """
    Deploy the zeth contracts and record the instantiation details.
    """
    eth_address = load_eth_address(eth_addr)
    eth_private_key_data = load_eth_private_key(eth_private_key)
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
        eth_private_key_data,
        token_address,
        deploy_gas_value)

    mixer_desc = MixerDescription(mixer_instance_desc, token_instance_desc)
    write_mixer_description(instance_out, mixer_desc)
