#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from coordinator.icontributionhandler import IContributionHandler

import os
import os.path

CONTRIBUTION_FILE_NAME = "contrib"
FINAL_FILE_NAME = "final-upload"


class NullContributionHandler(IContributionHandler):
    """
    A null handler that accepts contributions and simply stores them as
    subsequent challenges. When the MPC has completed, the latest contribution
    is moved to 'final-upload'. Can be used for testing coordinator
    configuration (certificate setup, etc).
    """

    def get_current_challenge_file(self, _next_contributor_idx: int) -> str:
        return CONTRIBUTION_FILE_NAME

    def process_contribution(
            self, _contributionn_idx: int, file_name: str) -> bool:
        os.rename(file_name, CONTRIBUTION_FILE_NAME)
        return True

    def on_completed(self) -> None:
        assert not os.path.exists(FINAL_FILE_NAME)
        if os.path.exists(CONTRIBUTION_FILE_NAME):
            os.rename(CONTRIBUTION_FILE_NAME, FINAL_FILE_NAME)
        else:
            print("WARNING: no contributions found")
