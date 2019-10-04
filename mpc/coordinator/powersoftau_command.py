#!/usr/bin/env python3

from os.path import exists, join, dirname
from typing import Optional, List

# These paths are hard-coded into the powersoftau code commands
CHALLENGE_FILE = "challenge"
NEW_CHALLENGE_FILE = "new_challenge"
RESPONSE_FILE = "response"


class PowersOfTauCommand(object):
    """
    Wrapper around the powersoftau commands
    """
    def __init__(self, powersoftau_path: Optional[str]):
        self.powersoftau_path = powersoftau_path or _default_powersoftau_path()
        self.bin_path = join(self.powersoftau_path, "target", "release")
        assert exists(self.bin_path)

    def begin(self) -> bool:
        return self._exec("new")

    def verify_contribution(self) -> bool:
        return self._exec("verify_transfrom")

    def append_response_to_transcript(
            self,
            response: str,
            transcript_file: str) -> None:
        import subprocess
        with open(transcript_file, "wb+") as transcript_f:
            subprocess.run(
                ["dd", f"if={response}", "bs=64", "skip=1"],
                stdout=transcript_f,
                check=True)

    def verify_transcript(self) -> bool:
        return self._exec("verify")

    def _exec(self, cmd: str, args: List[str] = list()) -> bool:
        import subprocess
        args = [join(self.bin_path, cmd)] + args
        return 0 == subprocess.run(args).returncode


def _default_powersoftau_path() -> str:
    return join(dirname(__file__), "..", "..", "..", "powersoftau")
