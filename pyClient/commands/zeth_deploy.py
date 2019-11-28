from commands.constants import INSTANCEFILE_DEFAULT
from commands.utils import open_web3_from_ctx, write_zeth_instance
from zeth.constants import ZETH_MERKLE_TREE_DEPTH
from zeth.prover_client import ProverClient
from zeth.joinsplit import ZethClient
from zeth.zksnark import IZKSnarkProvider
from click import command, argument, option, pass_context
from typing import Any


@command()
@argument("eth-address")
@option(
    "--instance-out",
    default=INSTANCEFILE_DEFAULT,
    help=f"File to write deployment address to (default={INSTANCEFILE_DEFAULT})")
@pass_context
def deploy(ctx: Any, eth_address: str, instance_out: str) -> None:
    """
    Deploy the zeth contracts and record the instantiation details.
    """
    print(f"deploy: eth_address={eth_address}")
    print(f"deploy: instance_out={instance_out}")

    web3 = open_web3_from_ctx(ctx)
    prover_client: ProverClient = ctx.obj["PROVER_CLIENT"]
    zksnark: IZKSnarkProvider = ctx.obj["ZKSNARK"]
    zeth_client = ZethClient.deploy(
        web3,
        prover_client,
        ZETH_MERKLE_TREE_DEPTH,
        eth_address,
        zksnark)

    write_zeth_instance(zeth_client.mixer_instance, instance_out)
