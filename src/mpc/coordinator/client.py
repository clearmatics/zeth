#!/usr/bin/env python3

from .crypto import \
    VerificationKey, Signature, export_digest, export_verification_key, \
    export_signature
from requests import post, get
from os.path import join

CHUNK_SIZE = 4096


class Client(object):

    def __init__(self, base_url: str):
        self.base_url = base_url

    def get_challenge(self, challenge_file: str) -> None:
        """
        GET /challenge request, downloading to file
        """
        with get(join(self.base_url, "challenge"), stream=True) as req:
            req.raise_for_status()
            with open(challenge_file, "wb") as out_f:
                for chunk in req.iter_content(chunk_size=CHUNK_SIZE):
                    out_f.write(chunk)

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
