#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
import zeth.joinsplit as joinsplit
from zeth.contracts import EncryptedNote, get_merkle_leaf
from zeth.utils import short_commitment
from api.util_pb2 import ZethNote
from nacl.public import PrivateKey, PublicKey  # type: ignore
from nacl import encoding  # type: ignore
from os.path import join
from typing import List, Tuple, Optional, Iterator, Any
import json


class ZethNoteDescription:
    """
    All data about a ZethNote owned by this wallet, including address in the
    merkle tree, and the commit value.
    """
    def __init__(self, note: ZethNote, address: int, commitment: bytes):
        self.note = note
        self.address = address
        self.commitment = commitment

    def as_input(self) -> Tuple[int, ZethNote]:
        """
        Returns the description in a form suitable for joinsplit.
        """
        return (self.address, self.note)


class Wallet:
    def __init__(
            self,
            mixer_instance: Any,
            username: str,
            wallet_dir: str,
            k_sk_receiver: PrivateKey):
        self.mixer_instance = mixer_instance
        self.username = username
        self.wallet_dir = wallet_dir
        self.k_sk_receiver = k_sk_receiver
        self.k_sk_receiver_bytes = \
            k_sk_receiver.encode(encoder=encoding.RawEncoder)

    def receive_notes(
            self,
            encrypted_notes: List[EncryptedNote],
            k_pk_sender: PublicKey) -> List[ZethNoteDescription]:
        """
        Decrypt any notes we can, verify them as being valid, and store them in
        the database.
        """
        new_notes = []
        for addr, note in self._decrypt_notes(encrypted_notes, k_pk_sender):
            note_desc = self._check_note(addr, note)
            if note_desc:
                self._write_note(note_desc)
                new_notes.append(note_desc)
        return new_notes

    def _decrypt_notes(
            self,
            encrypted_notes: List[EncryptedNote],
            k_pk_sender: PublicKey) -> Iterator[Tuple[int, ZethNote]]:
        """
        Check notes, returning an iterator over the ones we can successfully
        decrypt.
        """
        return joinsplit.receive_notes(
            encrypted_notes, k_pk_sender, self.k_sk_receiver)

    def _check_note(
            self, addr: int, note: ZethNote) -> Optional[ZethNoteDescription]:
        """
        Recalculate the note commitment that should have been stored in the
        Merkle tree, and check that the commitment is at the correct address.
        """
        cm = joinsplit.compute_commitment(note)
        mk_leaf = get_merkle_leaf(self.mixer_instance, addr)
        if mk_leaf != cm:
            print(f"WARN: bad commitment mk_leaf={mk_leaf.hex()}, cm={cm.hex()}")
            return None
        return ZethNoteDescription(note, addr, cm)

    def _write_note(self, note_desc: ZethNoteDescription) -> None:
        """
        Write a note to the database (currently just a file-per-note).
        """
        note_filename = join(self.wallet_dir, self._note_basename(note_desc))
        with open(note_filename, "w") as note_f:
            note_f.write(json.dumps(joinsplit.parse_zeth_note(note_desc.note)))

    def _note_basename(self, note_desc: ZethNoteDescription) -> str:
        value_eth = joinsplit.from_zeth_units(
            int(note_desc.note.value, 16)).ether()
        cm_str = short_commitment(note_desc.commitment)
        return f"note_{self.username}_{cm_str}_{value_eth}eth"
