#!/usr/bin/env python3

from __future__ import annotations
from .crypto import \
    VerificationKey, import_verification_key, export_verification_key, \
    Signature, import_signature, export_signature, check_key_evidence
import json
import time
from typing import List, Dict, cast, Optional

JsonDict = Dict[str, object]

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


class Contributor(object):
    """
    Details of a specific contributor
    """
    def __init__(
            self,
            email: str,
            verification_key: VerificationKey,
            key_evidence: Signature):
        self.email = email
        self.verification_key = verification_key
        self.key_evidence = key_evidence

    def _to_json_dict(self) -> JsonDict:
        return {
            "email": self.email,
            "verification_key": export_verification_key(self.verification_key),
            "key_evidence": export_signature(self.key_evidence),
        }

    @staticmethod
    def _from_json_dict(json_dict: JsonDict) -> Contributor:
        return Contributor(
            cast(str, json_dict["email"]),
            import_verification_key(cast(str, json_dict["verification_key"])),
            import_signature(cast(str, json_dict["key_evidence"])))


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
            port: int = 5000,
            email_server: Optional[str] = None,
            email_address: Optional[str] = None,
            email_password: Optional[str] = None):
        if 0 == start_time:
            raise Exception("invalid start time")
        if (email_server or email_address or email_password) and \
           (not (email_server and email_address and email_password)):
            raise Exception(
                "must all or none of email server, address and password " +
                "in config")

        self.contributors: List[Contributor] = contributors
        self.start_time: float = float(start_time)
        self.contribution_interval: float = float(contribution_interval)
        self.email_server: Optional[str] = email_server
        self.email_address: Optional[str] = email_address
        self.email_password: Optional[str] = email_password
        self.tls_key: str = tls_key
        self.tls_certificate: str = tls_certificate
        self.port = port

    @staticmethod
    def template(contributors: List[Contributor]) -> Configuration:
        """
        Populate contributors field, and other fields with sensible defaults
        for a configuration template.  All fields are expected to be
        overridden.
        """
        return Configuration(
            contributors=contributors,
            start_time=time.time() + 6 * 60 * 60,
            contribution_interval=24 * 60 * 60,
            tls_key="key.pem",
            tls_certificate="cert.pem",
            port=5000,
            email_server="smtp.mymail.com:465",
            email_address="mpc_coordinator@mymail.com",
            email_password="*")

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict(), indent=4)

    def to_json_template(self) -> str:
        """
        For the case where ana administrator has a list of contributors (e.g.
        from an online form) and keys and wants to import it into a
        server_config.json file. This function writes the contributors
        correctly, and places dummy data / descriptions in other fields,
        prefixed with '_', for the admin to fill in later.
        """
        return json.dumps(self._to_json_template_dict(), indent=4)

    @staticmethod
    def from_json(config_json: str) -> Configuration:
        return Configuration._from_json_dict(json.loads(config_json))

    def ensure_validity(self) -> None:
        """
        Checks the server configuration.  If there are any problems, throw an
        exception with a message.
        """

        # Evidence is expected to be the signature of
        # KEY_VALIDATION_CHECK_STRING.  Check this for all the contributors
        # keys
        for c in self.contributors:
            if not check_key_evidence(c.verification_key, c.key_evidence):
                raise Exception(f"Key for {c.email} has invalid evidence")

    def get_contributor_index(
            self,
            verification_key: VerificationKey) -> Optional[int]:
        """
        Return the index of the contributor, if present.
        """
        key = export_verification_key(verification_key)
        try:
            return [export_verification_key(c.verification_key)
                    for c in self.contributors].index(key)
        except ValueError:
            return None

    def _to_json_dict(self) -> JsonDict:
        start_local = time.localtime(self.start_time)
        return {
            "contributors": [c._to_json_dict() for c in self.contributors],
            "start_time": time.strftime(TIME_FORMAT, start_local),
            "contribution_interval": str(self.contribution_interval),
            "email_server": self.email_server,
            "email_address": self.email_address,
            "email_password": self.email_password,
            "tls_key": self.tls_key,
            "tls_certificate": self.tls_certificate,
            "port": self.port,
        }

    def _to_json_template_dict(self) -> JsonDict:
        start_local = time.localtime(self.start_time)
        return {
            "contributors": [c._to_json_dict() for c in self.contributors],
            "help":
            "This is a generated template. Populate the fields below, " +
            "removing _REQUIRED_ and _OPTIONAL_ prefixes as necessary.",
            "_REQUIRED_start_time": time.strftime(TIME_FORMAT, start_local),
            "_REQUIRED_contribution_interval": str(self.contribution_interval),
            "_OPTIONAL_email_server": self.email_server,
            "_OPTIONAL_email_address": self.email_address,
            "_OPTIONAL_email_password": self.email_password,
            "_REQUIRED_tls_key": self.tls_key,
            "_REQUIRED_tls_certificate": self.tls_certificate,
            "_REQUIRED_port": self.port,
        }

    @staticmethod
    def _from_json_dict(json_dict: JsonDict) -> Configuration:
        contributors_json_list = cast(List[JsonDict], json_dict["contributors"])
        start_local = time.strptime(
            cast(str, json_dict["start_time"]),
            TIME_FORMAT)
        return Configuration(
            [Contributor._from_json_dict(c) for c in contributors_json_list],
            time.mktime(start_local),
            float(cast(str, json_dict["contribution_interval"])),
            email_server=cast(str, json_dict.get("email_server", None)),
            email_address=cast(str, json_dict.get("email_address", None)),
            email_password=cast(str, json_dict.get("email_password", None)),
            tls_key=cast(str, json_dict["tls_key"]),
            tls_certificate=cast(str, json_dict["tls_certificate"]),
            port=int(cast(int, json_dict["port"])))
