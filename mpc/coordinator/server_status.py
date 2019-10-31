#!/usr/bin/env python3

from __future__ import annotations
from .server_configuration import Configuration, JsonDict
from .server_state import ServerState
import json
from typing import cast


class ServerStatus(object):
    """
    Model representing the response from the /status endpoint
    """
    def __init__(self, config: Configuration, state: ServerState):
        self.config = config
        self.state = state

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict(), indent=4)

    @staticmethod
    def from_json(status_json: str) -> ServerStatus:
        return ServerStatus._from_json_dict(json.loads(status_json))

    def _to_json_dict(self) -> JsonDict:
        return {
            "config": self.config._to_json_dict(),
            "state": self.state._to_json_dict(),
        }

    @staticmethod
    def _from_json_dict(json_dict: JsonDict) -> ServerStatus:
        configuration = Configuration._from_json_dict(
            cast(JsonDict, json_dict["config"]))
        return ServerStatus(
            configuration,
            ServerState._from_json_dict(
                configuration, cast(JsonDict, json_dict["state"])))
