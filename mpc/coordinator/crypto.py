#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
import ecdsa  # type: ignore
from Crypto.Hash import SHA512  # pylint: disable=no-name-in-module, import-error


HASH = SHA512
HASH_BYTE_LENGTH = 64
CURVE = ecdsa.NIST521p
VerificationKey = ecdsa.VerifyingKey
SigningKey = ecdsa.SigningKey
Signature = bytes

HASH_FILE_BLOCK_SIZE = 4096


def _compute_key_validation_digest() -> bytes:
    h = HASH.new()
    h.update(KEY_VALIDATION_CHECK_STRING.encode())
    return h.digest()


KEY_VALIDATION_CHECK_STRING: str = "Zeth MPC"
KEY_VALIDATION_CHECK_DIGEST: bytes = _compute_key_validation_digest()


def export_digest(digest: bytes) -> str:
    """
    Digest to string
    """
    assert len(digest) == HASH_BYTE_LENGTH
    return digest.hex()


def import_digest(digest_s: str) -> bytes:
    """
    Digest from string
    """
    if len(digest_s) != 2 * HASH_BYTE_LENGTH:
        raise Exception(f"unexpected digest string length: {len(digest_s)}")
    assert len(digest_s) == 2 * HASH_BYTE_LENGTH
    return bytes.fromhex(digest_s)


def generate_signing_key() -> ecdsa.SigningKey:
    return ecdsa.SigningKey.generate(curve=CURVE)


def export_signing_key(sk: ecdsa.SigningKey) -> bytes:
    return sk.to_der()


def import_signing_key(sk_b: bytes) -> ecdsa.SigningKey:
    return ecdsa.SigningKey.from_der(sk_b)


def get_verification_key(sk: ecdsa.SigningKey) -> ecdsa.VerifyingKey:
    return sk.get_verifying_key()


def export_verification_key(vk: ecdsa.VerifyingKey) -> str:
    return vk.to_der().hex()


def import_verification_key(vk_s: str) -> ecdsa.VerifyingKey:
    return ecdsa.VerifyingKey.from_der(bytes.fromhex(vk_s))


def export_signature(sig: bytes) -> str:
    return sig.hex()


def import_signature(sig_s: str) -> bytes:
    return bytes.fromhex(sig_s)


def compute_file_digest(file_name: str) -> bytes:
    h = HASH.new()
    with open(file_name, "rb") as file_f:
        while True:
            block = file_f.read(HASH_FILE_BLOCK_SIZE)
            if not block:
                return h.digest()
            h.update(block)


def sign(sk: ecdsa.SigningKey, digest: bytes) -> bytes:
    return sk.sign_digest(digest)


def verify(sig: bytes, vk: ecdsa.VerifyingKey, digest: bytes) -> bool:
    try:
        return vk.verify_digest(sig, digest)
    except Exception:
        return False


def create_key_evidence(key: ecdsa.SigningKey) -> Signature:
    return sign(key, KEY_VALIDATION_CHECK_DIGEST)


def check_key_evidence(
        verification_key: ecdsa.VerificationKey,  # pylint: disable=no-member
        key_evidence: Signature) -> bool:
    return verify(key_evidence, verification_key, KEY_VALIDATION_CHECK_DIGEST)
