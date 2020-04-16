#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from typing import NewType

from zeth.constants import KDF_TAG, EC_PUBLIC_KEY_LENGTH, SYM_KEY_LENGTH,\
    NOTE_LENGTH, TAG_LENGTH, SYM_NONCE_VALUE, SYM_NONCE_LENGTH,\
    ENCRYPTED_NOTE_LENGTH
from zeth.utils import bits_to_bytes_len

from cryptography.hazmat.primitives.asymmetric.x25519 \
    import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat,\
    PublicFormat, NoEncryption


# Encryption constants byte length
_PK_BYTE_LENGTH = bits_to_bytes_len(EC_PUBLIC_KEY_LENGTH)
_SYM_KEY_BYTE_LENGTH = bits_to_bytes_len(SYM_KEY_LENGTH)
_SYM_NONCE_BYTE_LENGTH = bits_to_bytes_len(SYM_NONCE_LENGTH)
_NOTE_BYTE_LENGTH = bits_to_bytes_len(NOTE_LENGTH)
_TAG_BYTE_LENGTH = bits_to_bytes_len(TAG_LENGTH)
_ENCRYPTED_NOTE_BYTE_LENGTH = bits_to_bytes_len(ENCRYPTED_NOTE_LENGTH)


# Represents a secret key for encryption
EncryptionSecretKey = NewType('EncryptionSecretKey', object)


def encode_encryption_secret_key(sk: EncryptionSecretKey) -> bytes:
    return sk.private_bytes(    # type: ignore
        Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def decode_encryption_secret_key(sk_bytes: bytes) -> EncryptionSecretKey:
    return EncryptionSecretKey(
        X25519PrivateKey.from_private_bytes(sk_bytes))


def encryption_secret_key_as_hex(sk: EncryptionSecretKey) -> str:
    return encode_encryption_secret_key(sk).hex()  # type: ignore


def encryption_secret_key_from_hex(pk_str: str) -> EncryptionSecretKey:
    return EncryptionSecretKey(
        X25519PrivateKey.from_private_bytes(bytes.fromhex(pk_str)))


def generate_encryption_secret_key() -> EncryptionSecretKey:
    return EncryptionSecretKey(
        X25519PrivateKey.generate())  # type: ignore


# Public key for decryption
EncryptionPublicKey = NewType('EncryptionPublicKey', object)


def encode_encryption_public_key(pk: EncryptionPublicKey) -> bytes:
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)  # type: ignore


def decode_encryption_public_key(pk_data: bytes) -> EncryptionPublicKey:
    return EncryptionPublicKey(
        X25519PublicKey.from_public_bytes(pk_data))


def encryption_public_key_as_hex(pk: EncryptionPublicKey) -> str:
    return encode_encryption_public_key(pk).hex()


def encryption_public_key_from_hex(pk_str: str) -> EncryptionPublicKey:
    return decode_encryption_public_key(bytes.fromhex(pk_str))


def get_encryption_public_key(
        enc_secret: EncryptionSecretKey) -> EncryptionPublicKey:
    return enc_secret.public_key()  # type: ignore


class EncryptionKeyPair:
    """
    Key-pair for encrypting joinsplit notes.
    """
    def __init__(self, k_sk: EncryptionSecretKey, k_pk: EncryptionPublicKey):
        self.k_pk: EncryptionPublicKey = k_pk
        self.k_sk: EncryptionSecretKey = k_sk


def generate_encryption_keypair() -> EncryptionKeyPair:
    sk = generate_encryption_secret_key()
    return EncryptionKeyPair(sk, get_encryption_public_key(sk))


def kdf(eph_pk: bytes, shared_key: bytes) -> bytes:
    """
    Key derivation function
    """
    # Hashing
    key_material = hashes.Hash(
        hashes.BLAKE2b(64),
        backend=default_backend())
    key_material.update(KDF_TAG)
    key_material.update(eph_pk)
    key_material.update(shared_key)
    digest = key_material.finalize()

    return digest


def get_private_key_from_bytes(sk_bytes: bytes) -> EncryptionSecretKey:
    """
    Gets PrivateKey object from raw representation
    """
    return EncryptionSecretKey(
        X25519PrivateKey.from_private_bytes(sk_bytes))


def get_public_key_from_bytes(pk_bytes: bytes) -> EncryptionPublicKey:
    """
    Gets PublicKey object from raw representation
    """
    return EncryptionPublicKey(
        X25519PublicKey.from_public_bytes(pk_bytes))


def exchange(sk: EncryptionSecretKey, pk: EncryptionPublicKey) -> bytes:
    return sk.exchange(pk)  # type: ignore


def encrypt(message: bytes, pk_receiver: EncryptionPublicKey) -> bytes:
    """
    Encrypts a string message under a ec25519 public key
    by using a custom dhaes-based scheme.
    See: https://eprint.iacr.org/1999/007
    """
    assert \
        len(message) == _NOTE_BYTE_LENGTH, \
        "message byte-length must be equal to: "+str(_NOTE_BYTE_LENGTH)

    # Generate ephemeral keypair
    eph_keypair = generate_encryption_keypair()

    # Compute shared secret and eph key
    shared_key = exchange(eph_keypair.k_sk, pk_receiver)
    pk_sender_bytes = encode_encryption_public_key(eph_keypair.k_pk)

    # Generate key material
    key_material = kdf(pk_sender_bytes, shared_key)

    # Generate symmetric ciphertext
    # Chacha encryption
    sym_key = key_material[:_PK_BYTE_LENGTH]
    mac_key = key_material[_PK_BYTE_LENGTH:]
    nonce = (SYM_NONCE_VALUE).to_bytes(_SYM_NONCE_BYTE_LENGTH, byteorder='little')
    algorithm = algorithms.ChaCha20(sym_key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    sym_ciphertext = encryptor.update(message)

    # Generate mac
    mac = poly1305.Poly1305(mac_key)
    mac.update(sym_ciphertext)
    tag = mac.finalize()

    # Arrange ciphertext
    return pk_sender_bytes+sym_ciphertext+tag


def decrypt(
        encrypted_message: bytes,
        sk_receiver: EncryptionSecretKey) -> bytes:
    """
    Decrypts a NOTE_LENGTH-byte message by using valid ec25519 private key
    objects.  See: https://pynacl.readthedocs.io/en/stable/public/
    """
    assert \
        len(encrypted_message) == _ENCRYPTED_NOTE_BYTE_LENGTH, \
        "encrypted_message byte-length must be: "+str(_ENCRYPTED_NOTE_BYTE_LENGTH)

    assert(isinstance(sk_receiver, X25519PrivateKey)), \
        f"PrivateKey: {sk_receiver} ({type(sk_receiver)})"

    # Compute shared secret
    pk_sender_bytes = encrypted_message[:_PK_BYTE_LENGTH]
    pk_sender = decode_encryption_public_key(pk_sender_bytes)
    shared_key = exchange(sk_receiver, pk_sender)

    # Generate key material and recover keys
    key_material = kdf(pk_sender_bytes, shared_key)
    sym_key = key_material[:_SYM_KEY_BYTE_LENGTH]
    mac_key = key_material[_SYM_KEY_BYTE_LENGTH:]

    # ct_sym and mac
    ct_sym = encrypted_message[
        _PK_BYTE_LENGTH:
        _PK_BYTE_LENGTH + _NOTE_BYTE_LENGTH]
    tag = encrypted_message[
        _PK_BYTE_LENGTH + _NOTE_BYTE_LENGTH:
        _PK_BYTE_LENGTH + _NOTE_BYTE_LENGTH + _TAG_BYTE_LENGTH]

    # Verify the mac
    mac = poly1305.Poly1305(mac_key)
    mac.update(ct_sym)
    mac.verify(tag)

    # Decrypt sym ciphertext
    nonce = (SYM_NONCE_VALUE).to_bytes(_SYM_NONCE_BYTE_LENGTH, byteorder='little')
    algorithm = algorithms.ChaCha20(sym_key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    message = decryptor.update(ct_sym)

    return message
