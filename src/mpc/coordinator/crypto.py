#!/usr/bin/env python3

import ecdsa                    # type: ignore
from Crypto.Hash import SHA512


HASH = SHA512
HASH_LENGTH = 64
CURVE = ecdsa.NIST521p
VerificationKey = ecdsa.VerifyingKey
Signature = bytes


def export_digest(digest: bytes) -> str:
    """
    Digest to string
    """
    assert len(digest) == HASH_LENGTH
    return digest.hex()


def import_digest(digest_s: str) -> bytes:
    """
    Digest from string
    """
    assert len(digest_s) == 2 * HASH_LENGTH
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


def sign(sk: ecdsa.SigningKey, digest: bytes) -> bytes:
    return sk.sign_digest(digest)


def verify(sig: bytes, vk: ecdsa.VerifyingKey, digest: bytes) -> bool:
    return vk.verify_digest(sig, digest)
