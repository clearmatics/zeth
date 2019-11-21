from commands.constants import KEYFILE_DEFAULT
from click import command, option
from typing import List, Any


@command()
@option("--in", "inputs", multiple=True)
@option("--out", "outputs", multiple=True)
@option("--key-file", default=KEYFILE_DEFAULT)
def send(ctx: Any, inputs: List[str], outputs: List[str], key_file: str) -> None:
    """
    Send notes to zethAddresses
    """
    print(f"send: host={ctx.obj['HOST']}")
    print(f"send: inputs={inputs}")
    print(f"send: outputs={outputs}")
    print(f"send: key_file={key_file}")
