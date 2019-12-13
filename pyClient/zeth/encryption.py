#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from nacl.public import PrivateKey  # type: ignore
import nacl.encoding  # type: ignore
from typing import NewType

# Thin wrapper around the nacl PublicKey and PrivateKey.  Note nacl doesn't
# include much type information, so we try to enforce strict types.


# Represents a PublicKey from
EncryptionSecretKey = NewType('EncryptionSecretKey', object)


# EncryptionPublicKey = PublicKey
EncryptionPublicKey = NewType('EncryptionPublicKey', object)


class EncryptionKeyPair:
    """
    Key-pair for encrypting joinsplit notes.
    """
    def __init__(self, k_sk: EncryptionSecretKey, k_pk: EncryptionPublicKey):
        self.k_pk: EncryptionPublicKey = k_pk
        self.k_sk: EncryptionSecretKey = k_sk


def encode_encryption_public_key(pk: EncryptionPublicKey) -> bytes:
    return pk.encode(encoder=nacl.encoding.RawEncoder)  # type: ignore


def get_encryption_public_key(
        enc_secret: EncryptionSecretKey) -> EncryptionPublicKey:
    return enc_secret.public_key  # type: ignore


def generate_encryption_secret_key() -> EncryptionSecretKey:
    return PrivateKey.generate()  # type: ignore


def generate_encryption_keypair() -> EncryptionKeyPair:
    sk = generate_encryption_secret_key()
    return EncryptionKeyPair(sk, get_encryption_public_key(sk))
