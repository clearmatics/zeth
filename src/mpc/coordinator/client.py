#!/usr/bin/env python3

from .crypto import \
    VerificationKey, Signature, export_digest, export_verification_key, \
    export_signature
from requests import post, get
from os.path import join
import time

CHUNK_SIZE = 4096


class Client(object):

    def __init__(self, base_url: str):
        self.base_url = base_url

    def get_challenge(self, challenge_file: str) -> None:
        """
        GET /challenge request, downloading to file
        """
        # Contributors should be notified of their turn AFTER processing has
        # completed on the previous contribution.  However, it's possible for
        # the next contributor, knowing his turn is next, to be waiting for
        # processing to complete.  Hence we loop with a message if the server
        # claims to be temporarily unavailable.
        while True:
            with get(join(self.base_url, "challenge"), stream=True) as resp:
                if 503 == resp.status_code:
                    print("server is busy.  retrying ...")
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
            r = post(
                join(self.base_url, "contribute"),
                files={'response': upload_f},
                headers=headers)
            r.raise_for_status()
