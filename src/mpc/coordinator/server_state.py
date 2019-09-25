from __future__ import annotations
from typing import List, Dict, Optional, cast
import json
from .crypto import \
    VerificationKey, import_verification_key, export_verification_key

JsonDict = Dict[str, object]

# 24 hours per contributor
CONTRIBUTION_INTERVAL = 24 * 60 * 60


class Contributor(object):
    """
    Details of a specific contributor
    """
    def __init__(self, email: str, public_key: VerificationKey):
        self.email = email
        self.public_key = public_key

    def to_json_dict(self) -> JsonDict:
        return {
            "email": self.email,
            "public_key": export_verification_key(self.public_key),
        }

    @staticmethod
    def from_json_dict(json_dict: JsonDict) -> Contributor:
        return Contributor(
            cast(str, json_dict["email"]),
            import_verification_key(cast(str, json_dict["public_key"])))


class ServerState(object):

    def __init__(
            self,
            contributors: List[Contributor],
            next_contributor_index: int,
            next_contributor_deadline: float):
        self.contributors: List = contributors
        self.next_contributor_index: int = next_contributor_index
        self.next_contributor_deadline: float = next_contributor_deadline

    @staticmethod
    def new(contributors: List[Contributor], start_time: float) -> ServerState:
        return ServerState(contributors, 0, start_time + CONTRIBUTION_INTERVAL)

    def to_json_dict(self) -> JsonDict:
        return {
            "contributors": [c.to_json_dict() for c in self.contributors],
            "next_contributor_index": self.next_contributor_index,
            "next_contributor_deadline": str(self.next_contributor_deadline),
        }

    @staticmethod
    def from_json_dict(json_dict: JsonDict) -> ServerState:
        contributors_json_list = cast(List[JsonDict], json_dict["contributors"])
        return ServerState(
            [Contributor.from_json_dict(c) for c in contributors_json_list],
            cast(int, json_dict["next_contributor_index"]),
            float(cast(str, json_dict["next_contributor_deadline"])))

    def have_all_contributions(self) -> bool:
        """
        returns True if all contributions have been received
        """
        return len(self.contributors) <= self.next_contributor_index

    def get_next_contribution_public_key(self) -> Optional[VerificationKey]:
        nc = self._next_contributor()
        return nc and nc.public_key

    def received_contribution(self, now: float) -> None:
        """
        Update the state after new contribution has been successfully received.
        """
        assert not self.have_all_contributions()
        self.next_contributor_index = self.next_contributor_index + 1
        self._update_deadline(now)

    def update(self, now: float) -> bool:
        """
        Check whether a contributor has missed his chance.  If the next deadline
        has not passed, do nothing and return False.  If the deadline has
        passed, update state and
        """
        # If the next contributor deadline has passed,
        if now < self.next_contributor_deadline:
            return False

        self.next_contributor_index = self.next_contributor_index + 1
        self._update_deadline(now)
        return True

    def _next_contributor(self) -> Optional[Contributor]:
        if len(self.contributors) > self.next_contributor_index:
            return self.contributors[self.next_contributor_index]
        return None

    def _update_deadline(self, now: float) -> None:
        if self.have_all_contributions():
            self.next_contributor_deadline = 0.0
        else:
            self.next_contributor_deadline = now + CONTRIBUTION_INTERVAL


def _server_state_to_json(state: ServerState) -> str:
    return json.dumps(state.to_json_dict())


def _server_state_from_json(state_json: str) -> ServerState:
    return ServerState.from_json_dict(json.loads(state_json))
