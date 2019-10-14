#!/usr/bin/env python3

from os.path import exists, join, dirname
from typing import Optional, List, Mapping

# These paths are hard-coded into the powersoftau code commands
CHALLENGE_FILE = "challenge"
NEW_CHALLENGE_FILE = "new_challenge"
RESPONSE_FILE = "response"

CONFIG = "release"


class PowersOfTauCommand(object):
    """
    Wrapper around the powersoftau commands
    """
    def __init__(
            self,
            powersoftau_path: Optional[str],
            num_powers: Optional[int]):
        self.powersoftau_path = powersoftau_path or _default_powersoftau_path()
        self.bin_path = join(self.powersoftau_path, "target", CONFIG)
        self.num_powers = num_powers
        if not exists(self.bin_path):
            raise Exception(f"expected bin path: {self.bin_path}")

    def begin(self) -> bool:
        return self._exec("new")

    def verify_contribution(self) -> bool:
        return self._exec("verify_transform")

    def append_response_to_transcript(
            self,
            response: str,
            transcript_file: str) -> None:
        import subprocess
        with open(transcript_file, "ab") as transcript_f:
            subprocess.run(
                ["dd", f"if={response}", "bs=64", "skip=1"],
                stdout=transcript_f,
                check=True)

    def contribute(
            self,
            digest_file: Optional[str],
            skip_user_input: bool) -> bool:
        assert exists(CHALLENGE_FILE)
        cmd_args: List[str] = []
        kwargs = {}
        if digest_file:
            cmd_args += ["--digest", digest_file]
        if skip_user_input:
            kwargs["input"] = "any data\n".encode()
        if self._exec("compute", cmd_args, kwargs):
            assert exists(RESPONSE_FILE)
            return True
        return False

    def verify_transcript(self, num_rounds: int) -> bool:
        return self._exec("verify", args=["--rounds", str(num_rounds)])

    def _exec(
            self,
            cmd: str,
            args: List[str] = list(),
            kwargs: Mapping[str, object] = {}) -> bool:
        import subprocess
        args = [join(self.bin_path, cmd)] + args
        if self.num_powers:
            args = args + ["-n", str(self.num_powers)]
        print(f"CMD: {' '.join(args)}")
        return 0 == subprocess.run(args=args, **kwargs).returncode


def _default_powersoftau_path() -> str:
    return join(dirname(__file__), "..", "..", "..", "powersoftau")
