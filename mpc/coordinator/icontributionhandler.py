#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
IContributionHandler interface
"""

# pylint: disable=unnecessary-pass

from abc import (ABC, abstractmethod)


class IContributionHandler(ABC):
    """
    Interface that must be implemented by handlers processing contributions
    """

    @abstractmethod
    def get_current_challenge_file(self, contributor_idx: int) -> str:
        """
        Return the location of the current challenge to serve.
        """
        pass

    @abstractmethod
    def process_contribution(
            self, contribution_idx: int, file_name: str) -> bool:
        """
        Process the given uploaded file as a contribution. If any errors are
        found, throw an exception with an appropriate message, or return false.
        """
        pass

    @abstractmethod
    def on_completed(self) -> None:
        """
        All contributions have been received and the MPC is complete.
        """
        pass
