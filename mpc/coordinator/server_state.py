#!/usr/bin/env python3

from __future__ import annotations
from .server_configuration import JsonDict, Configuration
from .contributor_list import ContributorList
from typing import cast
import json


class ServerState:
    """
    Current state of the server
    """
    def __init__(
            self,
            next_contributor_index: int,
            num_contributors: int,
            next_contributor_deadline: float):
        self.next_contributor_index: int = next_contributor_index
        self.num_contributors: int = num_contributors
        self.next_contributor_deadline: float = next_contributor_deadline
        assert self.num_contributors != 0

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    @staticmethod
    def from_json(state_json: str) -> ServerState:
        return ServerState._from_json_dict(
            json.loads(state_json))

    def have_all_contributions(self) -> bool:
        """
        returns True if all contributions have been received
        """
        return self.num_contributors <= self.next_contributor_index

    def received_contribution(self, next_deadline: float) -> None:
        """
        Update the state after new contribution has been successfully received.
        """
        assert not self.have_all_contributions()
        self._next_contributor(next_deadline)

    def update(self, now: float, interval: float) -> bool:
        """
        Check whether a contributor has missed his chance and update internal
        state accordingly. If the deadline has passed, return True. Otherwise
        return False.
        """
        # If the next contributor deadline has passed, update
        if self.next_contributor_deadline <= 0.0 or \
           now < self.next_contributor_deadline:
            return False

        self._next_contributor(now + interval)
        return True

    def _next_contributor(self, next_deadline: float) -> None:
        self.next_contributor_index = self.next_contributor_index + 1
        if self.have_all_contributions():
            self.next_contributor_deadline = 0.0
        else:
            self.next_contributor_deadline = next_deadline

    def _to_json_dict(self) -> JsonDict:
        return {
            "next_contributor_index": self.next_contributor_index,
            "num_contributors": self.num_contributors,
            "next_contributor_deadline": str(self.next_contributor_deadline),
        }

    @staticmethod
    def _from_json_dict(json_dict: JsonDict) -> ServerState:
        return ServerState(
            next_contributor_index=cast(int, json_dict["next_contributor_index"]),
            num_contributors=cast(int, json_dict["num_contributors"]),
            next_contributor_deadline=float(
                cast(str, json_dict["next_contributor_deadline"])))


def initial_server_state(
        configuration: Configuration,
        contributors: ContributorList) -> ServerState:
    """
    Create an initial server state, given a configuration and contributor list.
    """
    assert configuration.start_time != 0.0
    assert configuration.contribution_interval != 0.0
    assert len(contributors) != 0
    state = ServerState(
        0,
        len(contributors),
        configuration.start_time + configuration.contribution_interval)
    return state
