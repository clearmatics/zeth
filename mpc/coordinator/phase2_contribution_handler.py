#!/usr/bin/env python3

"""
Implementation of Phase2ContributionHandler
"""

from coordinator.icontributionhandler import IContributionHandler
from coordinator.mpc_command import MPCCommand
from os.path import exists, join
from os import rename
from typing import Optional

CHALLENGE_0_FILE = "challenge_0.bin"
NEXT_CHALLENGE_FILE = "next_challenge.bin"
NEW_CHALLENGE_FILE = "new_challenge.bin"
TRANSCRIPT_FILE = "transcript.bin"
FINAL_OUTPUT = "final_output.bin"
FINAL_TRANSCRIPT = "final_transcript.bin"


class Phase2ContributionHandler(IContributionHandler):
    """
    Handler processing phase2 challenges and contributions.
    """

    def __init__(self, bin_path: Optional[str] = None) -> None:
        # Sanity check
        if not exists(CHALLENGE_0_FILE):
            raise Exception(f"no {CHALLENGE_0_FILE} found in server dir")

        # If there is no NEXT_CHALLENGE, there should also be no TRANSCRIPT
        if not exists(NEXT_CHALLENGE_FILE):
            if exists(TRANSCRIPT_FILE):
                raise Exception(f"unexpected {TRANSCRIPT_FILE} in server dir")

        mpc_exe = join(bin_path, "mpc") if bin_path else None
        self.mpc = MPCCommand(mpc_exe)

    def get_current_challenge_file(self, contributor_idx: int) -> str:
        # If there is no NEXT_CHALLENGE_FILE, use CHALLENGE_0_FILE.  (Note,
        # contributor_idx may be > 0, even if there is no NEXT_CHALLENGE_FILE.
        # The only condition related ot contributor_idx is that, if
        # contributor_idx is 0, we MUST ONLY have the initial challenge.)
        have_next_challenge = exists(NEXT_CHALLENGE_FILE)
        if have_next_challenge:
            if 0 == contributor_idx:
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

            # Contribution has been recorded in TRANSCRIPT_FILE.  Replace
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
