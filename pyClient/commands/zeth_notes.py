from commands.constants import ZETH_NOTESFILE_DEFAULT
from click import command, option
from typing import Any


@command()
@option(
    "--notes-file",
    default=ZETH_NOTESFILE_DEFAULT,
    help=f"Zeth notes file (\"{ZETH_NOTESFILE_DEFAULT}\")")
def sync(ctx: Any, notes_file: str) -> None:
    """
    List the set of notes owned by this wallet
    """
    print(f"notes: host={ctx.obj['HOST']}")
    print(f"notes: notes_file={notes_file}")
