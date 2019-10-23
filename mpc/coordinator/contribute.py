#!/usr/bin/env python3

"""
Functions performing the common steps of contribution: download challenge,
sign and upload response.
"""


from coordinator.client import Client
from coordinator.crypto import \
    read_contribution_digest, import_signing_key, get_verification_key, sign, \
    SigningKey
from typing import Callable, Optional, Tuple


def _upload_response(
        client: Client,
        response_file: str,
        response_digest_file: str,
        sk: SigningKey) -> None:
    # Compute digest and sign
    digest = read_contribution_digest(response_digest_file)
    signature = sign(sk, digest)
    vk = get_verification_key(sk)

    # Upload
    client.push_contribution(response_file, digest, vk, signature)


def upload_response(
        client: Client,
        response_file: str,
        response_digest_file: str,
        key_file: str) -> None:
    """
    Given some response file and a key, sign the response and upload the
    coordinator connected to by client.
    """
    with open(key_file, "rb") as key_f:
        sk = import_signing_key(key_f.read())
    _upload_response(client, response_file, response_digest_file, sk)


def contribute(
        base_url: str,
        key_file: str,
        challenge_file: str,
        contribute_cb: Callable[[], Tuple[str, str]],
        server_certificate: Optional[str],
        insecure: bool) -> None:
    """
    Given a callback that creates a response from a challenge, download a
    challenge, create the response via the callback, and sign and upload it.
    """
    # Check key upfront
    with open(key_file, "rb") as key_f:
        sk = import_signing_key(key_f.read())
    print("got key")

    client = Client(base_url, server_certificate, insecure)

    # Get challenge
    client.get_challenge(challenge_file)
    print("got challenge")

    # Perform the contribution
    response_file, response_digest_file = contribute_cb()

    # Sign and upload
    _upload_response(client, response_file, response_digest_file, sk)
