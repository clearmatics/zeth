from commands.constants import INSTANCEFILE_DEFAULT
from commands.utils import \
    open_web3_from_ctx, write_contract_instance, load_eth_address
from zeth.constants import ZETH_MERKLE_TREE_DEPTH
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
@pass_context
def deploy(ctx: Any, eth_addr: Optional[str], instance_out: str) -> None:
    """
    Deploy the zeth contracts and record the instantiation details.
    """
    eth_address = load_eth_address(eth_addr)
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

    write_contract_instance(zeth_client.mixer_instance, instance_out)
