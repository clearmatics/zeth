#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from .crypto import \
    VerificationKey, Signature, export_digest, export_verification_key, \
    export_signature
from .server_state import ServerState
from .contributor_list import ContributorList
from typing import Optional, Union
from requests import post, get, Response
from os.path import join, exists
import time

CHUNK_SIZE = 4096
SERVER_BUSY_503_CLIENT_MSG = "Server is busy. Retrying ..."


class Client:

    def __init__(
            self,
            base_url: str,
            cert_path: Optional[str] = None,
            insecure: bool = False):
        assert not cert_path or exists(cert_path)
        self.base_url = base_url
        self.verify: Union[bool, str, None] = False if insecure else cert_path

    def get_contributors(self) -> ContributorList:
        """
        GET /contributors
        Get the status of the server.
        """
        while True:
            resp = get(join(self.base_url, "contributors"), verify=self.verify)
            if resp.status_code == 503:
                print(SERVER_BUSY_503_CLIENT_MSG)
                time.sleep(5.0)
                continue

            resp.raise_for_status()
            return ContributorList.from_json(resp.content.decode())

    def get_state(self) -> ServerState:
        """
        GET /state
        Get the status of the server.
        """
        while True:
            resp = get(join(self.base_url, "state"), verify=self.verify)
            if resp.status_code == 503:
                print(SERVER_BUSY_503_CLIENT_MSG)
                time.sleep(5.0)
                continue

            resp.raise_for_status()
            return ServerState.from_json(resp.content.decode())

    def get_challenge(self, challenge_file: str) -> None:
        """
        GET /challenge request, downloading to file
        """
        # Contributors should be notified of their turn AFTER processing has
        # completed on the previous contribution. However, it's possible for
        # the next contributor, knowing his turn is next, to be waiting for
        # processing to complete. Hence we loop with a message if the server
        # claims to be temporarily unavailable.
        def _get_challenge() -> Response:
            return get(
                join(self.base_url, "challenge"),
                stream=True,
                verify=self.verify)

        while True:
            with _get_challenge() as resp:
                if resp.status_code == 503:
                    print(SERVER_BUSY_503_CLIENT_MSG)
                    time.sleep(5.0)
                    continue

                resp.raise_for_status()
                with open(challenge_file, "wb") as out_f:
                    for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                        out_f.write(chunk)
                break

    def push_contribution(
            self,
            response_file: str,
            response_digest: bytes,
            verification_key: VerificationKey,
            signature: Signature) -> None:
        """
        POST /contribute, uploading from file with all authentication headers
        """
        headers = {
            'X-MPC-Digest': export_digest(response_digest),
            'X-MPC-Public-Key': export_verification_key(verification_key),
            'X-MPC-Signature': export_signature(signature),
        }
        with open(response_file, "rb") as upload_f:
            resp = post(
                join(self.base_url, "contribute"),
                files={'response': upload_f},
                headers=headers,
                verify=self.verify)
            resp.raise_for_status()
