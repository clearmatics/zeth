#!/usr/bin/env python3

from coordinator.icontributionhandler import IContributionHandler

import os
import os.path

CONTRIBUTION_FILE_NAME = "contrib"
FINAL_FILE_NAME = "final-upload"


class NullContributionHandler(IContributionHandler):
    """
    A null handler that accepts contributions and simple stores them as
    challenges.  When the MPC has completed, the latest contribution is moved
    to
    """

    def get_current_challenge_file(self) -> str:
        return CONTRIBUTION_FILE_NAME

    def process_contribution(self, file_name: str) -> bool:
        os.rename(file_name, CONTRIBUTION_FILE_NAME)
        return True

    def on_completed(self) -> None:
        assert not os.path.exists(FINAL_FILE_NAME)
        if os.path.exists(CONTRIBUTION_FILE_NAME):
            os.rename(CONTRIBUTION_FILE_NAME, FINAL_FILE_NAME)
        else:
            print("WARNING: no contributions found")
