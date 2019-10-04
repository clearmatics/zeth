#!/usr/bin/env python3

from coordinator.client import Client
from coordinator.crypto import \
    compute_file_digest, import_signing_key, get_verification_key, sign
from typing import Callable, Optional


def contribute(
        base_url: str,
        key_file: str,
        challenge_file: str,
        contribute: Callable[[], str],
        server_certificate: Optional[str]) -> None:
    """
    Given a callback that creates a response from a challenge, download a
    challenge, create the response via the callback, and sign and upload it.
    """
    # Check key upfront
    with open(key_file, "rb") as key_f:
        sk = import_signing_key(key_f.read())
    print("got key")

    # Get challenge
    client = Client(base_url, server_certificate)
    client.get_challenge(challenge_file)
    print("got challenge")

    # Perform the contribution
    response_file = contribute()

    # Compute digest and sign
    digest = compute_file_digest(response_file)
    signature = sign(sk, digest)
    vk = get_verification_key(sk)

    # Upload
    client.push_contribution(response_file, digest, vk, signature)
