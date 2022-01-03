#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Implementation of Phase2ContributionHandler
"""

from __future__ import annotations
from .server_configuration import Configuration, JsonDict
from .icontributionhandler import IContributionHandler
from .mpc_command import MPCCommand
from .phase1_contribution_handler import \
    NEW_CHALLENGE_FILE, TRANSCRIPT_FILE, FINAL_OUTPUT, FINAL_TRANSCRIPT

from os.path import exists
from os import rename
from typing import Optional, cast
import json

CHALLENGE_0_FILE = "challenge_0.bin"
NEXT_CHALLENGE_FILE = "next_challenge.bin"


class Phase2ServerConfig:
    """
    Configuration object for phase2 server.
    """

    def __init__(
            self,
            server_configuration: Configuration,
            mpc_tool: Optional[str]):
        self.server_configuration = server_configuration
        self.mpc_tool = mpc_tool

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict(), indent=4)

    @staticmethod
    def from_json(
            phase2_config_json: str,
            config_path: Optional[str] = None) -> Phase2ServerConfig:
        return Phase2ServerConfig._from_json_dict(
            json.loads(phase2_config_json), config_path)

    def _to_json_dict(self) -> JsonDict:
        return {
            "server": self.server_configuration._to_json_dict(),
            "mpc_tool": self.mpc_tool,
        }

    @staticmethod
    def _from_json_dict(
            json_dict: JsonDict,
            config_path: Optional[str]) -> Phase2ServerConfig:
        return Phase2ServerConfig(
            server_configuration=Configuration._from_json_dict(
                cast(JsonDict, json_dict["server"]), config_path),
            mpc_tool=cast(Optional[str], json_dict.get("mpc_tool", None)))


class Phase2ContributionHandler(IContributionHandler):
    """
    Handler processing phase2 challenges and contributions.
    """

    def __init__(self, phase2_config: Phase2ServerConfig):
        # Sanity check
        if not exists(CHALLENGE_0_FILE):
            raise Exception(f"no {CHALLENGE_0_FILE} found in server dir")

        # If there is no NEXT_CHALLENGE, there should also be no TRANSCRIPT
        if not exists(NEXT_CHALLENGE_FILE):
            if exists(TRANSCRIPT_FILE):
                raise Exception(f"unexpected {TRANSCRIPT_FILE} in server dir")

        self.mpc = MPCCommand(phase2_config.mpc_tool)

    def get_current_challenge_file(self, contributor_idx: int) -> str:
        # If there is no NEXT_CHALLENGE_FILE, use CHALLENGE_0_FILE. (Note,
        # contributor_idx may be > 0, even if there is no NEXT_CHALLENGE_FILE.
        # The only condition related to contributor_idx is that, if
        # contributor_idx is 0, we MUST ONLY have the initial challenge.)
        have_next_challenge = exists(NEXT_CHALLENGE_FILE)
        if have_next_challenge:
            if contributor_idx == 0:
                raise Exception(
                    f"unexpected {NEXT_CHALLENGE_FILE} for 0-th contributor")
            return NEXT_CHALLENGE_FILE
        return CHALLENGE_0_FILE

    def process_contribution(
            self, contribution_idx: int, file_name: str) -> bool:
        orig_challenge = self.get_current_challenge_file(contribution_idx)
        contribution_valid = self.mpc.phase2_verify_contribution(
            orig_challenge=orig_challenge,
            response=file_name,
            out_new_challenge=NEW_CHALLENGE_FILE,
            transcript=TRANSCRIPT_FILE)

        if contribution_valid:
            if not exists(NEW_CHALLENGE_FILE):
                raise Exception("unknown error creating new challenge")

            # Contribution has been recorded in TRANSCRIPT_FILE. Replace
            # NEXT_CHALLENGE_FILE with NEW_CHALLENGE_FILE.
            rename(NEW_CHALLENGE_FILE, NEXT_CHALLENGE_FILE)
            return True

        return False

    def on_completed(self) -> None:
        # Confirm that there has been at least one contribution, otherwise the
        # MPC is invalid.
        if not exists(NEXT_CHALLENGE_FILE):
            raise Exception("no contributions made")

        # Perform a validation of the full transcript
        mpc_valid = self.mpc.phase2_verify_transcript(
            CHALLENGE_0_FILE,
            NEXT_CHALLENGE_FILE,
            TRANSCRIPT_FILE)
        if not mpc_valid:
            raise Exception("error in MPC transcript")

        # If all is well, move the final challenge file
        rename(NEXT_CHALLENGE_FILE, FINAL_OUTPUT)
        rename(TRANSCRIPT_FILE, FINAL_TRANSCRIPT)

        # Notify that handler execution completed
        print("Phase 2 coordinator correctly executed.")
        print("(CTRL-C to stop the server)")
