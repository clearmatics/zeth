from commands.constants import WALLET_DIR_DEFAULT, KEYFILE_DEFAULT
from commands.utils import load_zeth_instance, open_wallet
from click import command, option, pass_context
from typing import Any


@command()
@option(
    "--wallet-dir",
    default=WALLET_DIR_DEFAULT,
    help=f"Wallet direcetory (\"{WALLET_DIR_DEFAULT}\")")
@option("--key-file", default=KEYFILE_DEFAULT)
@pass_context
def notes(ctx: Any, wallet_dir: str, key_file: str) -> None:
    """
    List the set of notes owned by this wallet
    """

    mixer_instance = load_zeth_instance(ctx.obj["INSTANCE_FILE"])
    wallet = open_wallet(mixer_instance, key_file, wallet_dir)
    print(f"Notes for wallet dir: {wallet_dir}")
    for addr, short_commit, value in wallet.note_summaries():
        print(f"{short_commit}: value={value.ether()}, addr={addr}")
