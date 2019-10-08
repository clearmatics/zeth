#!/usr/bin/env python3

"""
Implementation of Phase1ContributionHandler
"""

from .icontributionhandler import IContributionHandler
from .powersoftau_command import \
    PowersOfTauCommand, CHALLENGE_FILE, NEW_CHALLENGE_FILE, RESPONSE_FILE
from os.path import exists
from os import rename
from typing import Optional

TRANSCRIPT_FILE = "transcript"
FINAL_OUTPUT = "final_output.bin"
FINAL_TRANSCRIPT = "final_transcript.bin"


class Phase1ContributionHandler(IContributionHandler):
    """
    Handler processing phase1 (powersoftau) challenges and contributions.
    """

    def __init__(
            self,
            powersoftau_path: Optional[str] = None,
            num_powers: Optional[int] = None) -> None:

        self.powersoftau = PowersOfTauCommand(powersoftau_path, num_powers)

        # Create challenge file if it does not exist.
        if not exists(CHALLENGE_FILE):
            assert not exists(NEW_CHALLENGE_FILE)
            assert not exists(TRANSCRIPT_FILE)
            print("phase1: creating initial challenge ...")
            self.powersoftau.begin()
        assert exists(CHALLENGE_FILE)

        # TODO: How will the transcript be handled?

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

            # concat part of response into transcript
            self.powersoftau.append_response_to_transcript(
                RESPONSE_FILE, TRANSCRIPT_FILE)

            # move new_challenge ot be the next challenge
            rename(NEW_CHALLENGE_FILE, CHALLENGE_FILE)
            return True

        return False

    def on_completed(self) -> None:
        # Confirm that there has been at least one contribution, otherwise the
        # MPC is invalid.
        if not exists(TRANSCRIPT_FILE):
            raise Exception("no contributions made")

        # Perform a validation of the full transcript
        mpc_valid = self.powersoftau.verify_transcript()
        if not mpc_valid:
            raise Exception("error in MPC transcript")

        # If all is well, move the final challenge file
        rename(CHALLENGE_FILE, FINAL_OUTPUT)
        rename(TRANSCRIPT_FILE, FINAL_TRANSCRIPT)
