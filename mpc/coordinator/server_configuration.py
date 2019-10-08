#!/usr/bin/env python3

from __future__ import annotations
from .crypto import \
    VerificationKey, import_verification_key, export_verification_key
import json
from typing import List, Dict, cast

JsonDict = Dict[str, object]


class Contributor(object):
    """
    Details of a specific contributor
    """
    def __init__(self, email: str, verification_key: VerificationKey):
        self.email = email
        self.verification_key = verification_key

    def _to_json_dict(self) -> JsonDict:
        return {
            "email": self.email,
            "verification_key": export_verification_key(self.verification_key),
        }

    @staticmethod
    def _from_json_dict(json_dict: JsonDict) -> Contributor:
        return Contributor(
            cast(str, json_dict["email"]),
            import_verification_key(cast(str, json_dict["verification_key"])))


class Configuration(object):
    """
    Static configuration provided at startup
    """
    def __init__(
            self,
            contributors: List[Contributor],
            start_time: float,
            contribution_interval: float,
            tls_key: str,
            tls_certificate: str,
            port: int = 5000):
        assert 0 != start_time
        self.contributors: List[Contributor] = contributors
        self.start_time: float = float(start_time)
        self.contribution_interval: float = float(contribution_interval)
        self.tls_key: str = tls_key
        self.tls_certificate: str = tls_certificate
        self.port = port

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    @staticmethod
    def from_json(config_json: str) -> Configuration:
        return Configuration._from_json_dict(json.loads(config_json))

    def _to_json_dict(self) -> JsonDict:
        return {
            "contributors": [c._to_json_dict() for c in self.contributors],
            "start_time": str(self.start_time),
            "contribution_interval": str(self.contribution_interval),
            "tls_key": self.tls_key,
            "tls_certificate": self.tls_certificate,
            "port": self.port,
        }

    @staticmethod
    def _from_json_dict(json_dict: JsonDict) -> Configuration:
        contributors_json_list = cast(List[JsonDict], json_dict["contributors"])
        return Configuration(
            [Contributor._from_json_dict(c) for c in contributors_json_list],
            float(cast(str, json_dict["start_time"])),
            float(cast(str, json_dict["contribution_interval"])),
            tls_key=cast(str, json_dict["tls_key"]),
            tls_certificate=cast(str, json_dict["tls_certificate"]),
            port=int(cast(int, json_dict["port"])))
