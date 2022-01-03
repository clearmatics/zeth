#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Functions for processing public keys, common to multiple commands.
"""

from coordinator.crypto import \
    SigningKey, get_verification_key, \
    export_verification_key, \
    create_key_evidence, export_signature
from typing import Optional
from os.path import exists


def public_key_information(
        key: SigningKey,
        public_key_file: Optional[str],
        evidence_file: Optional[str]) -> None:
    """
    Print (and optionally save) public information about a private key.
    """

    if public_key_file and exists(public_key_file):
        raise Exception("public key file already exists")
    if evidence_file and exists(evidence_file):
        raise Exception("evidence file already exists")

    pub_key = get_verification_key(key)
    key_evidence = create_key_evidence(key)
    pub_key_str = export_verification_key(pub_key)
    evidence_str = export_signature(key_evidence)

    if public_key_file:
        with open(public_key_file, "w") as pk_f:
            pk_f.write(pub_key_str)
    if evidence_file:
        with open(evidence_file, "w") as ev_f:
            ev_f.write(evidence_str)

    print("Public Verification Key:")
    print(pub_key_str)
    print("\nKey Evidence:")
    print(evidence_str)
