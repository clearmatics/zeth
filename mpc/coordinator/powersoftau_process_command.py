#!/usr/bin/env python3

from typing import Optional, List
# from

CONFIG = "release"


class PowersOfTauProcessCommand(object):
    """
    Wrapper around the pot-process command.
    """

    def __init__(self, pot_process_executable: Optional[str] = None):
        self.bin_path = pot_process_executable or _default_executable()

    def compute_lagrange(
            self,
            pot_file: str,
            degree: int,
            lagrange_output_file: str) -> bool:
        return self._exec(["--out", lagrange_output_file, pot_file, str(degree)])

    def _exec(self, args: List[str]) -> bool:
        import subprocess
        args = [self.bin_path] + args
        print(f"CMD: {' '.join(args)}")
        return 0 == subprocess.run(args=args).returncode


def _default_executable() -> str:
    from os.path import join, dirname
    return join(dirname(__file__), "..", "..", "build", "src", "pot-process")
