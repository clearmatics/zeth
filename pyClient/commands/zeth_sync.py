from commands.utils import open_web3_from_ctx, load_zeth_instance, \
    load_zeth_address_secret, open_wallet, do_sync
from click import command, option, pass_context
from typing import Optional, Any


@command()
@option("--wait-tx", help="Wait for tx hash")
@pass_context
def sync(ctx: Any, wait_tx: Optional[str]) -> None:
    """
    Attempt to retrieve new notes for the key in <key-file>
    """
    web3 = open_web3_from_ctx(ctx)
    mixer_instance = load_zeth_instance(ctx, web3)
    js_secret = load_zeth_address_secret(ctx)
    wallet = open_wallet(mixer_instance, js_secret, ctx)
    chain_block_number = do_sync(web3, wallet, wait_tx)
    print(f"SYNCED to {chain_block_number}")
