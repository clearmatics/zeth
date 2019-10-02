#!/usr/bin/env python3

from typing import Optional, List
from os.path import exists
import os.path
import subprocess

"""
Utility to invoke MPC command
"""


class MPCCommand(object):
    """
    Wrapper around the 'mpc' utility.
    """

    def __init__(self, mpc_exe: Optional[str] = ""):
        self.mpc_exe = mpc_exe or _default_mpc_bin()
        assert exists(self.mpc_exe)

    def phase2_verify_contribution(
            self,
            orig_challenge: str,
            response: str,
            out_new_challenge: Optional[str] = None,
            transcript: Optional[str] = None) -> bool:
        args = [
            "phase2-verify-contribution",
        ]
        if out_new_challenge is not None:
            args += ["--new-challenge", out_new_challenge]
        if transcript is not None:
            args += ["--transcript", transcript]
        args += [orig_challenge, response]
        return self._exec(args)

    def phase2_verify_transcript(
            self,
            orig_challenge: str,
            final_challenge: str,
            transcript: str,
            digest_file: Optional[str] = None) -> bool:
        args = ["phase2-verify-transcript"]
        if digest_file is not None:
            args += ["--digest", digest_file]
        args += [orig_challenge, transcript, final_challenge]
        return self._exec(args)

    def phase2_contribute(
            self,
            challenge_file: str,
            output_file: Optional[str] = None,
            digest_file: Optional[str] = None,
            skip_user_input: bool = False) -> bool:
        args = ["phase2-contribute", challenge_file]
        args += ["--out", output_file] if output_file else []
        args += ["--digest", digest_file] if digest_file else []
        args += ["--skip-user-input"] if output_file else []
        return self._exec(args)

    def _exec(self, args: List[str]) -> bool:
        cmd = [self.mpc_exe] + args
        print(f"CMD: {' '.join(cmd)}")
        comp = subprocess.run(cmd)
        return 0 == comp.returncode


def _default_mpc_bin() -> str:
    return os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "build",
        "src",
        "mpc",
        "mpc-test")
