#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
import zeth.joinsplit as joinsplit
from zeth.contracts import EncryptedNote, get_merkle_leaf
from zeth.utils import EtherValue, short_commitment
from api.util_pb2 import ZethNote
from nacl.public import PrivateKey, PublicKey  # type: ignore
from nacl import encoding  # type: ignore
from os.path import join, basename, exists
from os import makedirs
from typing import List, Tuple, Optional, Iterator, Any
import glob
import json


class ZethNoteDescription:
    """
    All secret data about a single ZethNote, including address in the merkle
    tree and the commit value.
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

    def to_json(self) -> str:
        json_dict = {
            "note": joinsplit.zeth_note_to_json_dict(self.note),
            "address": str(self.address),
            "commitment": self.commitment.hex(),
        }
        return json.dumps(json_dict, indent=4)

    @staticmethod
    def from_json(json_str: str) -> ZethNoteDescription:
        json_dict = json.loads(json_str)
        return ZethNoteDescription(
            note=joinsplit.zeth_note_from_json_dict(json_dict["note"]),
            address=int(json_dict["address"]),
            commitment=bytes.fromhex(json_dict["commitment"]))


class Wallet:
    """
    Very simple class to track a list of notes owned by a Zeth user. Note this
    does not store the notes in encrypted form, and encodes some information
    (including value) in the filename. It is NOT intended to be secure against
    intruders who have access to the file system, although such an
    implementation should be able to support an interface of this kind.
    """
    def __init__(
            self,
            mixer_instance: Any,
            username: str,
            wallet_dir: str,
            k_sk_receiver: PrivateKey):
        assert "_" not in username
        self.mixer_instance = mixer_instance
        self.username = username
        self.wallet_dir = wallet_dir
        self.k_sk_receiver = k_sk_receiver
        self.k_sk_receiver_bytes = \
            k_sk_receiver.encode(encoder=encoding.RawEncoder)
        self.state_file = join(wallet_dir, f"state_{username}")
        _ensure_dir(self.wallet_dir)

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

    def note_summaries(self) -> Iterator[Tuple[int, str, EtherValue]]:
        """
        Returns simple information that can be efficiently read from the notes
        store.
        """
        return self._decoded_note_filenames()

    def get_next_block(self) -> int:
        if exists(self.state_file):
            with open(self.state_file, "r") as state_f:
                return int(state_f.read())
        else:
            return 1

    def set_next_block(self, next_block: int) -> None:
        with open(self.state_file, "w") as state_f:
            state_f.write(str(next_block))

    def find_note(self, note_id: str) -> ZethNoteDescription:
        note_file = self._find_note_file(note_id)
        if not note_file:
            raise Exception(f"no note with id {note_id}")
        with open(note_file, "r") as note_f:
            return ZethNoteDescription.from_json(note_f.read())

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
            note_f.write(note_desc.to_json())

    def _note_basename(self, note_desc: ZethNoteDescription) -> str:
        value_eth = joinsplit.from_zeth_units(
            int(note_desc.note.value, 16)).ether()
        cm_str = short_commitment(note_desc.commitment)
        return "note_%s_%04d_%s_%s" % (
            self.username, note_desc.address, cm_str, value_eth)

    @staticmethod
    def _decode_basename(filename: str) -> Tuple[int, str, EtherValue]:
        components = filename.split("_")
        addr = int(components[2])
        short_commit = components[3]
        value = EtherValue(components[4], 'ether')
        return (addr, short_commit, value)

    def _decoded_note_filenames(self) -> Iterator[Tuple[int, str, EtherValue]]:
        wildcard = join(self.wallet_dir, f"note_{self.username}_*")
        filenames = sorted(glob.glob(wildcard))
        for filename in filenames:
            try:
                yield self._decode_basename(basename(filename))
                # print(f"wallet: _decoded_note_filenames: file={filename}")
            except ValueError:
                # print(f"wallet: _decoded_note_filenames: FAILED {filename}")
                continue

    def _find_note_file(self, key: str) -> Optional[str]:
        """
        Given some (fragment of) address or short commit, try to uniquely
        identify a note file.
        """
        # If len <= 4, assume it's an address, otherwise a commit
        if len(key) < 5:
            try:
                addr = "%04d" % int(key)
                wildcard = f"note_{self.username}_{addr}_*"
            except Exception:
                return None
        else:
            wildcard = f"note_{self.username}_*_{key}_*"

        candidates = list(glob.glob(join(self.wallet_dir, wildcard)))
        return candidates[0] if len(candidates) == 1 else None


def _ensure_dir(directory_name: str) -> None:
    if not exists(directory_name):
        makedirs(directory_name)
