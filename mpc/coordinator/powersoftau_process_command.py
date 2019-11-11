#!/usr/bin/env python3

from typing import Optional, List
# from

CONFIG = "release"


class PowersOfTauProcessCommand(object):
    """
    Wrapper around the pot-process command.
    """

    def __init__(self, pot_process_tool: Optional[str] = None):
        self.pot_process_tool = pot_process_tool or _default_tool()

    def compute_lagrange(
            self,
            pot_file: str,
            pot_degree: int,
            lagrange_output_file: str,
            lagrange_degree: Optional[int]) -> bool:
        lagrange_degree = lagrange_degree or pot_degree
        return self._exec(
            ["--out", lagrange_output_file,
             "--lagrange-degree", str(lagrange_degree),
             pot_file,
             str(pot_degree)])

    def _exec(self, args: List[str]) -> bool:
        import subprocess
        args = [self.pot_process_tool] + args
        print(f"CMD: {' '.join(args)}")
        return 0 == subprocess.run(args=args).returncode


def _default_tool() -> str:
    from os.path import join, dirname
    return join(dirname(__file__), "..", "..", "build", "src", "pot-process")
