from commands.constants import ZETH_KEYFILE_DEFAULT, ZETH_NOTESFILE_DEFAULT
from click import command, option
from typing import Any


@command()
@option(
    "--key-file",
    default=ZETH_KEYFILE_DEFAULT,
    help=f"Zeth keyfile (\"{ZETH_KEYFILE_DEFAULT}\")")
@option(
    "--notes-file",
    default=ZETH_NOTESFILE_DEFAULT,
    help=f"Zeth notes file (\"{ZETH_NOTESFILE_DEFAULT}\")")
def sync(ctx: Any, key_file: str, notes_file: str) -> None:
    """
    Attempt to retrieve new notes for the key in <key-file>
    """
    pass
