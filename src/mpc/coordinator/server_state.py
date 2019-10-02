#!/usr/bin/env python3

from __future__ import annotations
from typing import cast
import json
from .server_configuration import JsonDict, Configuration


class ServerState(object):
    """
    Current state of the server
    """
    def __init__(
            self,
            next_contributor_index: int,
            num_contributors: int,
            next_contributor_deadline: float):
        assert num_contributors != 0
        self.next_contributor_index: int = next_contributor_index
        self.num_contributors: int = num_contributors
        self.next_contributor_deadline: float = next_contributor_deadline

    @staticmethod
    def new(configuration: Configuration) -> ServerState:
        assert configuration.start_time != 0.0
        assert configuration.contribution_interval != 0.0
        return ServerState(
            0,
            len(configuration.contributors),
            configuration.start_time + configuration.contribution_interval)

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    @staticmethod
    def from_json(state_json: str) -> ServerState:
        return ServerState._from_json_dict(json.loads(state_json))

    def have_all_contributions(self) -> bool:
        """
        returns True if all contributions have been received
        """
        return self.num_contributors <= self.next_contributor_index

    def received_contribution(self, config: Configuration, now: float) -> None:
        """
        Update the state after new contribution has been successfully received.
        """
        assert not self.have_all_contributions()
        self.next_contributor_index = self.next_contributor_index + 1
        self._update_deadline(config, now)

    def update(self, config: Configuration, now: float) -> bool:
        """
        Check whether a contributor has missed his chance.  If the next deadline
        has not passed, do nothing and return False.  If the deadline has
        passed, update state and
        """
        # If the next contributor deadline has passed,
        if now < self.next_contributor_deadline:
            return False

        self.next_contributor_index = self.next_contributor_index + 1
        self._update_deadline(config, now)
        return True

    def _to_json_dict(self) -> JsonDict:
        return {
            "next_contributor_index": self.next_contributor_index,
            "num_contributors": self.num_contributors,
            "next_contributor_deadline": str(self.next_contributor_deadline),
        }

    @staticmethod
    def _from_json_dict(json_dict: JsonDict) -> ServerState:
        return ServerState(
            cast(int, json_dict["next_contributor_index"]),
            cast(int, json_dict["num_contributors"]),
            float(cast(str, json_dict["next_contributor_deadline"])))

    def _update_deadline(self, config: Configuration, now: float) -> None:
        if self.have_all_contributions():
            self.next_contributor_deadline = 0.0
        else:
            self.next_contributor_deadline = now + config.contribution_interval
