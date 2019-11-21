from commands.constants import INSTANCEFILE_DEFAULT
from commands.utils import write_instance_id
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
    Deploy the zeth contracts
    """
    print(f"deploy: eth_address={eth_address}")
    print(f"deploy: instance_out={instance_out}")

    prover_client: ProverClient = ctx.obj["PROVER_CLIENT"]
    zksnark: IZKSnarkProvider = ctx.obj["ZKSNARK"]
    zeth_client = ZethClient.deploy(
        prover_client,
        ZETH_MERKLE_TREE_DEPTH,
        eth_address,
        zksnark)

    write_instance_id(zeth_client.mixer_instance.address, instance_out)
