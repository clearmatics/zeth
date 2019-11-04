#!/usr/bin/env python3

from __future__ import annotations
import json
import time
from typing import Dict, cast, Optional

JsonDict = Dict[str, object]

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


class Configuration(object):
    """
    Static configuration provided at startup
    """
    def __init__(
            self,
            contributors_file: str,
            start_time: float,
            contribution_interval: float,
            tls_key: str,
            tls_certificate: str,
            port: int = 5000,
            email_server: Optional[str] = None,
            email_address: Optional[str] = None,
            email_password: Optional[str] = None):
        if not contributors_file:
            raise Exception("no contributors file specified")
        if 0 == start_time:
            raise Exception("invalid start time")
        if (email_server or email_address or email_password) and \
           (not (email_server and email_address and email_password)):
            raise Exception(
                "must all or none of email server, address and password " +
                "in config")

        self.contributors_file: str = contributors_file
        self.start_time: float = float(start_time)
        self.contribution_interval: float = float(contribution_interval)
        self.email_server: Optional[str] = email_server
        self.email_address: Optional[str] = email_address
        self.email_password: Optional[str] = email_password
        self.tls_key: str = tls_key
        self.tls_certificate: str = tls_certificate
        self.port = port

    @staticmethod
    def template() -> Configuration:
        """
        Populate contributors field, and other fields with sensible defaults
        for a configuration template.  All fields are expected to be
        overridden.
        """
        return Configuration(
            contributors_file="contributors.json",
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

    def _to_json_dict(self) -> JsonDict:
        start_local = time.localtime(self.start_time)
        return {
            "contributors_file": self.contributors_file,
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
            "contributors_file": self.contributors_file,
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
        start_local = time.strptime(
            cast(str, json_dict["start_time"]),
            TIME_FORMAT)
        return Configuration(
            cast(str, json_dict["contributors_file"]),
            time.mktime(start_local),
            float(cast(str, json_dict["contribution_interval"])),
            email_server=cast(str, json_dict.get("email_server", None)),
            email_address=cast(str, json_dict.get("email_address", None)),
            email_password=cast(str, json_dict.get("email_password", None)),
            tls_key=cast(str, json_dict["tls_key"]),
            tls_certificate=cast(str, json_dict["tls_certificate"]),
            port=int(cast(int, json_dict["port"])))
