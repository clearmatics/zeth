from click import command, argument, option, pass_context
from typing import Optional, Any


@command()
@argument("contract-dir")
@argument("eth-address")
@option("--instance-out", default=None, help="Write instance address to a file")
@option("--interface-out", help="Contract interface file")
@pass_context
def deploy(
        ctx: Any,
        contract_dir: str,
        eth_address: str,
        instance_out: Optional[str],
        interface_out: Optional[str]) -> None:
    """
    Deploy the zeth contracts
    """
    print(f"deploy: host={ctx.obj['HOST']}")
    print(f"deploy: contract_dir={contract_dir}")
    print(f"deploy: eth_address={eth_address}")
    print(f"deploy: instance_out={instance_out}")
    print(f"deploy: interface_out={interface_out}")
