from commands.zeth_deploy import deploy
from commands.zeth_deposit import deposit
from commands.zeth_sync import sync
from click import group, option, pass_context
from typing import Any, Optional


@group()
@option("--host", help="Ethereum node address host:rpc-port")
@pass_context
def zeth(ctx: Any, host: Optional[str]) -> None:
    ctx.ensure_object(dict)
    ctx.obj["HOST"] = host
    print(f"host is {host}")


zeth.add_command(deploy)
zeth.add_command(deposit)
zeth.add_command(sync)


if __name__ == "__main__":
    zeth()  # pylint: disable=no-value-for-parameter
