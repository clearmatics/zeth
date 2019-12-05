from commands.constants import INSTANCEFILE_DEFAULT
from commands.utils import \
    open_web3_from_ctx, get_erc20_instance_description, load_eth_address, \
    write_mixer_description, MixerDescription
from zeth.constants import ZETH_MERKLE_TREE_DEPTH
from zeth.contracts import InstanceDescription
from zeth.prover_client import ProverClient
from zeth.joinsplit import ZethClient
from zeth.zksnark import IZKSnarkProvider
from click import command, option, pass_context
from typing import Optional, Any


@command()
@option("--eth-addr", help="Sender eth address or address filename")
@option(
    "--instance-out",
    default=INSTANCEFILE_DEFAULT,
    help=f"File to write deployment address to (default={INSTANCEFILE_DEFAULT})")
@option("--token-address", help="Address of token contract (if used)")
@pass_context
def deploy(
        ctx: Any,
        eth_addr: Optional[str],
        instance_out: str,
        token_address: str) -> None:
    """
    Deploy the zeth contracts and record the instantiation details.
    """
    eth_address = load_eth_address(eth_addr)
    web3 = open_web3_from_ctx(ctx)

    print(f"deploy: eth_address={eth_address}")
    print(f"deploy: instance_out={instance_out}")
    print(f"deploy: token_address={token_address}")

    token_instance_desc = get_erc20_instance_description(token_address) \
        if token_address else None

    prover_client: ProverClient = ctx.obj["PROVER_CLIENT"]
    zksnark: IZKSnarkProvider = ctx.obj["ZKSNARK"]
    zeth_client = ZethClient.deploy(
        web3,
        prover_client,
        ZETH_MERKLE_TREE_DEPTH,
        eth_address,
        zksnark,
        token_address)

    mixer_instance_desc = \
        InstanceDescription.from_instance(zeth_client.mixer_instance)
    mixer_desc = MixerDescription(mixer_instance_desc, token_instance_desc)
    write_mixer_description(instance_out, mixer_desc)
