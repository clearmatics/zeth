from commands.constants import NOTESFILE_DEFAULT
from click import command, option
from typing import Any


@command()
@option("--notes-file", default=NOTESFILE_DEFAULT)
def balance(ctx: Any, notes_file: str) -> None:
    """
    Send notes to zethAddresses
    """
    print(f"balance: host={ctx.obj['HOST']}")
    print(f"balance: notes_file={notes_file}")
