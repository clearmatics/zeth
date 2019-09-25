#!/usr/bin/env python3

"""
IContributionHandler interface
"""

from abc import (ABC, abstractmethod)


class IContributionHandler(ABC):
    """
    Interface that must be implemented by handlers processing contributions
    """

    @abstractmethod
    def get_current_challenge_file(self) -> str:
        pass

    @abstractmethod
    def process_contribution(self, file_name: str) -> bool:
        pass
