from commands.constants import KEYFILE_DEFAULT, NOTESFILE_DEFAULT
from click import command, option
from typing import Any


@command()
@option(
    "--key-file",
    default=KEYFILE_DEFAULT,
    help=f"Zeth keyfile (\"{KEYFILE_DEFAULT}\")")
@option(
    "--notes-file",
    default=NOTESFILE_DEFAULT,
    help=f"Zeth notes file (\"{NOTESFILE_DEFAULT}\")")
def sync(ctx: Any, key_file: str, notes_file: str) -> None:
    """
    Attempt to retrieve new notes for the key in <key-file>
    """
    print(f"sync: host={ctx.obj['HOST']}")
    print(f"sync: key_file={key_file}")
    print(f"sync: notes_file={notes_file}")
