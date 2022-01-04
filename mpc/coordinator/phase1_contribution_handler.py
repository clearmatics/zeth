#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Implementation of Phase1ContributionHandler
"""

from __future__ import annotations
from .server_configuration import Configuration, JsonDict
from .icontributionhandler import IContributionHandler
from .powersoftau_command import \
    PowersOfTauCommand, CHALLENGE_FILE, NEW_CHALLENGE_FILE, RESPONSE_FILE
from os.path import exists
from os import rename
from typing import Optional, cast
import json

PHASE1_STATE_FILE = "phase1_state.json"

TRANSCRIPT_FILE = "transcript"
FINAL_OUTPUT = "final_output.bin"
FINAL_TRANSCRIPT = "final_transcript.bin"


class Phase1ServerConfig:
    """
    Configuration for Phase1 server
    """
    def __init__(
            self,
            server_configuration: Configuration,
            pot_path: Optional[str],
            num_powers: Optional[int]):
        self.server_configuration = server_configuration
        self.powersoftau_path = pot_path
        self.num_powers = num_powers

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict(), indent=4)

    @staticmethod
    def from_json(
            phase1_config_json: str,
            config_path: Optional[str] = None) -> Phase1ServerConfig:
        return Phase1ServerConfig._from_json_dict(
            json.loads(phase1_config_json), config_path)

    def _to_json_dict(self) -> JsonDict:
        return {
            "server": self.server_configuration._to_json_dict(),
            "powersoftau_path": self.powersoftau_path,
            "num_powers": self.num_powers,
        }

    @staticmethod
    def _from_json_dict(
            json_dict: JsonDict,
            config_path: Optional[str]) -> Phase1ServerConfig:
        return Phase1ServerConfig(
            server_configuration=Configuration._from_json_dict(
                cast(JsonDict, json_dict["server"]), config_path),
            pot_path=cast(Optional[str], json_dict.get("powersoftau_path", None)),
            num_powers=cast(Optional[int], json_dict.get("num_powers", None)))


class _Phase1State:
    """
    Internal persisted state model for this handler.
    """

    def __init__(self, num_valid_contributions: int):
        self.num_valid_contributions = num_valid_contributions

    @staticmethod
    def new() -> _Phase1State:
        return _Phase1State(0)

    def on_valid_contribution(self) -> None:
        self.num_valid_contributions = self.num_valid_contributions + 1

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    @staticmethod
    def from_json(state_json: str) -> _Phase1State:
        return _Phase1State._from_json_dict(json.loads(state_json))

    def _to_json_dict(self) -> JsonDict:
        return {
            "num_valid_contributions": self.num_valid_contributions,
        }

    @staticmethod
    def _from_json_dict(json_dict: JsonDict) -> _Phase1State:
        return _Phase1State(
            cast(int, json_dict["num_valid_contributions"]))


class Phase1ContributionHandler(IContributionHandler):
    """
    Handler processing phase1 (powersoftau) challenges and contributions. Some
    complexity is involved, because we need to track the number of valid
    contributions that have been made.
    """

    def __init__(self, phase1_config: Phase1ServerConfig):
        self.powersoftau = PowersOfTauCommand(
            phase1_config.powersoftau_path, phase1_config.num_powers)

        if exists(PHASE1_STATE_FILE):
            with open(PHASE1_STATE_FILE, "r") as state_f:
                self.state = _Phase1State.from_json(state_f.read())
        else:
            self.state = _Phase1State.new()

        # Create challenge file if it does not exist.
        if not exists(CHALLENGE_FILE):
            assert not exists(NEW_CHALLENGE_FILE)
            assert not exists(TRANSCRIPT_FILE)
            print("Phase1: creating initial challenge ...")
            self.powersoftau.begin()
        assert exists(CHALLENGE_FILE)

    def get_current_challenge_file(self, contributor_idx: int) -> str:
        # Single "challenge" file always contains the next challenge
        return CHALLENGE_FILE

    def process_contribution(
            self, contribution_idx: int, file_name: str) -> bool:

        rename(file_name, RESPONSE_FILE)
        contribution_valid = self.powersoftau.verify_contribution()
        if contribution_valid:
            if not exists(NEW_CHALLENGE_FILE):
                raise Exception("unknown error creating new challenge")

            # concatenate part of response into transcript
            self.powersoftau.append_response_to_transcript(
                RESPONSE_FILE, TRANSCRIPT_FILE)

            # update internal state
            self.state.on_valid_contribution()
            self._save_state()

            # move new_challenge to be the next challenge
            rename(NEW_CHALLENGE_FILE, CHALLENGE_FILE)
            return True

        return False

    def on_completed(self) -> None:
        # Confirm that there has been at least one contribution, otherwise the
        # MPC is invalid.
        if not exists(TRANSCRIPT_FILE):
            raise Exception("no contributions made")

        # Perform a validation of the full transcript
        mpc_valid = self.powersoftau.verify_transcript(
            self.state.num_valid_contributions)
        if not mpc_valid:
            raise Exception("error in MPC transcript")

        # If all is well, move the final challenge file
        rename(CHALLENGE_FILE, FINAL_OUTPUT)
        rename(TRANSCRIPT_FILE, FINAL_TRANSCRIPT)

        # Notify that handler execution completed
        print("Phase 1 coordinator correctly executed.")
        print("(CTRL-C to stop the server)")

    def _save_state(self) -> None:
        with open(PHASE1_STATE_FILE, "w") as state_f:
            state_f.write(self.state.to_json())
