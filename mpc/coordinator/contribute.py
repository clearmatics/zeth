#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Functions performing the common steps of contribution: download challenge,
sign and upload response.
"""

from coordinator.client import Client
from coordinator.crypto import \
    compute_file_digest, import_signing_key, get_verification_key, sign, \
    SigningKey, VerificationKey
from typing import Callable, Optional
import time
from requests.exceptions import RequestException


def _upload_response(client: Client, response_file: str, sk: SigningKey) -> None:
    # Compute digest and sign
    digest = compute_file_digest(response_file)
    signature = sign(sk, digest)
    vk = get_verification_key(sk)

    # Upload
    client.push_contribution(response_file, digest, vk, signature)


def upload_response(client: Client, response_file: str, key_file: str) -> None:
    """
    Given some response file and a key, sign the response and upload the
    coordinator connected to by client.
    """
    with open(key_file, "rb") as key_f:
        sk = import_signing_key(key_f.read())
    _upload_response(client, response_file, sk)


def wait_for_turn(
        client: Client,
        interval: int,
        verification_key: VerificationKey) -> None:
    """
    Wait until our turn, returning when we can contribute. If anything goes
    wrong, an exception is thrown.
    """
    contributors = client.get_contributors()
    our_idx = contributors.get_contributor_index(verification_key)
    while True:
        state = client.get_state()
        current_index = state.next_contributor_index
        if our_idx is None:
            raise Exception("contributor is not in the server list")
        if our_idx < current_index:
            raise Exception("contributor turn has passed")
        if our_idx == current_index:
            return
        # Wait for interval and try again
        print(f"Waiting ... (current_idx: {current_index}, our_idx: {our_idx})")
        time.sleep(interval)


def contribute(
        base_url: str,
        key_file: str,
        challenge_file: str,
        contribute_cb: Callable[[], str],
        wait_interval: int,
        server_certificate: Optional[str],
        insecure: bool) -> None:
    """
    Given a callback that creates a response from a challenge, download a
    challenge, create the response via the callback, and sign and upload it.
    """
    # Check key upfront
    with open(key_file, "rb") as key_f:
        sk = import_signing_key(key_f.read())
    print("Got key")

    client = Client(base_url, server_certificate, insecure)

    try:
        if wait_interval:
            verification_key = get_verification_key(sk)
            wait_for_turn(client, wait_interval, verification_key)

        # Get challenge
        client.get_challenge(challenge_file)
        print("Got challenge")

        # Perform the contribution
        response_file = contribute_cb()

    except RequestException as err:
        print(f"EXCEPTION: {err.response.status_code} - {err.response.text}")
        raise

    # Sign and upload
    _upload_response(client, response_file, sk)
