#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from .server_configuration import JsonDict
from .crypto import \
    VerificationKey, import_verification_key, export_verification_key, \
    Signature, import_signature, export_signature, check_key_evidence
from typing import List, cast, Optional
import json


class Contributor:
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


class ContributorList:
    """
    Model for contributors list file
    """
    def __init__(self, contributors: List[Contributor]):
        self.contributors = contributors

    def ensure_validity(self) -> None:
        """
        Checks the server configuration. If there are any problems, throw an
        exception with a message.
        """

        # Evidence is expected to be the signature of
        # KEY_VALIDATION_CHECK_STRING. Check this for all the contributors
        # keys
        for contr in self.contributors:
            if not check_key_evidence(contr.verification_key, contr.key_evidence):
                raise Exception(f"Key for {contr.email} has invalid evidence")

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

    def __getitem__(self, key: int) -> Contributor:
        return self.contributors[key]

    def __len__(self) -> int:
        return len(self.contributors)

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict(), indent=4)

    @staticmethod
    def from_json(json_str: str) -> ContributorList:
        return ContributorList._from_json_dict(json.loads(json_str))

    def _to_json_dict(self) -> JsonDict:
        return {
            "contributors": [contr._to_json_dict() for contr in self.contributors]
        }

    @staticmethod
    def _from_json_dict(json_dict: JsonDict) -> ContributorList:
        contributors_json = cast(List[JsonDict], json_dict["contributors"])
        return ContributorList(
            [Contributor._from_json_dict(c) for c in contributors_json])
