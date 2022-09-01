#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from typing import Optional, List
from os.path import exists
import os.path
import subprocess


class MPCCommand:
    """
    Wrapper around the 'mpc' utility.
    """

    def __init__(self, mpc_tool: Optional[str] = "", dry_run: bool = False):
        self.mpc_tool = mpc_tool or _default_mpc_tool()
        self.dry_run = dry_run
        assert exists(self.mpc_tool)

    def linear_combination(
            self,
            powersoftau_file: str,
            lagrange_file: str,
            linear_comb_out_file: str,
            pot_degree: Optional[int] = None) -> bool:
        args = ["linear-combination"]
        args += ["--pot-degree", str(pot_degree)] if pot_degree else []
        args += [powersoftau_file, lagrange_file, linear_comb_out_file]
        return self._exec(args)

    def phase2_begin(self, linear_comb_file: str, challenge_0_file: str) -> bool:
        return self._exec(["phase2-begin", linear_comb_file, challenge_0_file])

    def phase2_verify_contribution(
            self,
            orig_challenge: str,
            response: str,
            out_new_challenge: Optional[str] = None,
            transcript: Optional[str] = None) -> bool:
        args = ["phase2-verify-contribution"]
        args += ["--new-challenge", out_new_challenge] \
            if out_new_challenge else []
        args += ["--transcript", transcript] if transcript else []
        args += [orig_challenge, response]
        return self._exec(args)

    def phase2_verify_transcript(
            self,
            orig_challenge: str,
            final_challenge: str,
            transcript: str,
            digest_file: Optional[str] = None) -> bool:
        args = ["phase2-verify-transcript"]
        args += ["--digest", digest_file] if digest_file else []
        args += [orig_challenge, transcript, final_challenge]
        return self._exec(args)

    def phase2_contribute(
            self,
            challenge_file: str,
            output_file: str,
            digest_file: Optional[str] = None,
            skip_user_input: bool = False) -> bool:
        args = ["phase2-contribute", challenge_file, output_file]
        args += ["--digest", digest_file] if digest_file else []
        args += ["--skip-user-input"] if skip_user_input else []
        return self._exec(args)

    def create_keypair(
            self,
            powersoftau_file: str,
            linear_comb_file: str,
            final_challenge: str,
            keypair_out_file: str,
            pot_degree: Optional[int] = None) -> bool:
        args = ["create-keypair"]
        args += ["--pot-degree", str(pot_degree)] if pot_degree else []
        args += [
            powersoftau_file,
            linear_comb_file,
            final_challenge,
            keypair_out_file]
        return self._exec(args)

    def _exec(self, args: List[str]) -> bool:
        cmd = [self.mpc_tool] + args
        print(f"CMD: {' '.join(cmd)}")
        return self.dry_run or \
            subprocess.run(cmd, check=False).returncode == 0


def _default_mpc_tool() -> str:
    return os.path.join(
        os.path.dirname(__file__), "..", "..",
        "build", "mpc_tools", "mpc_phase2", "mpc-coord-phase2")
