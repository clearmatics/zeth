#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.zeth_address import ZethAddressPriv
from zeth.mixer_client import zeth_note_to_json_dict, zeth_note_from_json_dict, \
    receive_note, compute_nullifier, compute_commitment
from zeth.constants import ZETH_MERKLE_TREE_DEPTH
from zeth.contracts import MixOutputEvents
from zeth.merkle_tree import PersistentMerkleTree
from zeth.utils import EtherValue, short_commitment, from_zeth_units
from api.zeth_messages_pb2 import ZethNote
from os.path import join, basename, exists
from os import makedirs
from shutil import move
from typing import Dict, List, Tuple, Optional, Iterator, Any, cast
import glob
import json
import math


# pylint: disable=too-many-instance-attributes

SPENT_SUBDIRECTORY: str = "spent"
MERKLE_TREE_FILE: str = "merkle-tree.dat"

# Map nullifier to short commitment string identifying the commitment.
NullifierMap = Dict[str, str]


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
            "note": zeth_note_to_json_dict(self.note),
            "address": str(self.address),
            "commitment": self.commitment.hex(),
        }
        return json.dumps(json_dict, indent=4)

    @staticmethod
    def from_json(json_str: str) -> ZethNoteDescription:
        json_dict = json.loads(json_str)
        return ZethNoteDescription(
            note=zeth_note_from_json_dict(json_dict["note"]),
            address=int(json_dict["address"]),
            commitment=bytes.fromhex(json_dict["commitment"]))


class WalletState:
    """
    State to be saved in the wallet (excluding individual notes). As well as
    the next block to query, we store some information about the state of the
    Zeth deployment such as the number of notes or the number of distinct
    addresses seen. This can be useful to estimate the security of a given
    transaction.
    """
    def __init__(
            self, next_block: int, num_notes: int, nullifier_map: NullifierMap):
        self.next_block = next_block
        self.num_notes = num_notes
        self.nullifier_map = nullifier_map

    def to_json(self) -> str:
        json_dict = {
            "next_block": self.next_block,
            "num_notes": self.num_notes,
            "nullifier_map": self.nullifier_map,
        }
        return json.dumps(json_dict, indent=4)

    @staticmethod
    def from_json(json_str: str) -> WalletState:
        json_dict = json.loads(json_str)
        return WalletState(
            next_block=int(json_dict["next_block"]),
            num_notes=int(json_dict["num_notes"]),
            nullifier_map=cast(NullifierMap, json_dict["nullifier_map"]))


def _load_state_or_default(state_file: str) -> WalletState:
    if not exists(state_file):
        return WalletState(1, 0, {})
    with open(state_file, "r") as state_f:
        return WalletState.from_json(state_f.read())


def _save_state(state_file: str, state: WalletState) -> None:
    with open(state_file, "w") as state_f:
        state_f.write(state.to_json())


class Wallet:
    """
    Very simple class to track the list of notes owned by a Zeth user.

    Note: this class does not store the notes in encrypted form, and encodes
    some information (including value) in the filename. It is a proof of
    concept implementation and NOT intended to be secure against intruders who
    have access to the file system. However, we expect that a secure
    implementation could expose similar interface and functionality.
    """
    def __init__(
            self,
            mixer_instance: Any,
            username: str,
            wallet_dir: str,
            secret_address: ZethAddressPriv):
        # k_sk_receiver: EncryptionSecretKey):
        assert "_" not in username
        self.mixer_instance = mixer_instance
        self.username = username
        self.wallet_dir = wallet_dir
        self.a_sk = secret_address.a_sk
        self.k_sk_receiver = secret_address.k_sk
        self.state_file = join(wallet_dir, f"state_{username}")
        self.state = _load_state_or_default(self.state_file)
        _ensure_dir(join(self.wallet_dir, SPENT_SUBDIRECTORY))
        self.merkle_tree = PersistentMerkleTree.open(
            join(wallet_dir, MERKLE_TREE_FILE),
            int(math.pow(2, ZETH_MERKLE_TREE_DEPTH)))
        self.merkle_tree_changed = False
        self.next_addr = self.merkle_tree.get_num_entries()

    def receive_note(
            self,
            comm_addr: int,
            out_ev: MixOutputEvents) -> Optional[ZethNoteDescription]:
        # Check this output event to see if it belongs to this wallet.
        our_note = receive_note(out_ev, self.k_sk_receiver)
        if our_note is None:
            return None

        (commit, note) = our_note
        if not _check_note(commit, note):
            return None

        note_desc = ZethNoteDescription(note, comm_addr, commit)
        self._write_note(note_desc)

        # Add the nullifier to the map in the state file
        nullifier = compute_nullifier(note_desc.note, self.a_sk)
        self.state.nullifier_map[nullifier.hex()] = \
            short_commitment(commit)
        return note_desc

    def receive_notes(
            self,
            output_events: List[MixOutputEvents]) -> List[ZethNoteDescription]:
        """
        Decrypt any notes we can, verify them as being valid, and store them in
        the database.
        """
        new_notes = []

        self.merkle_tree_changed = len(output_events) != 0
        for out_ev in output_events:
            print(
                f"wallet.receive_notes: idx:{self.next_addr}, " +
                f"comm:{out_ev.commitment[:8].hex()}")

            # All commitments must be added to the tree in order.
            self.merkle_tree.insert(out_ev.commitment)
            note_desc = self.receive_note(self.next_addr, out_ev)
            if note_desc is not None:
                new_notes.append(note_desc)

            self.next_addr = self.next_addr + 1

        # Record full set of notes seen to keep an estimate of the total in the
        # mixer.
        self.state.num_notes = self.state.num_notes + len(output_events)

        return new_notes

    def mark_nullifiers_used(self, nullifiers: List[bytes]) -> List[str]:
        """
        Process nullifiers, marking any of our notes that they spend.
        """
        commits: List[str] = []
        for nullifier in nullifiers:
            nullifier_hex = nullifier.hex()
            short_commit = self.state.nullifier_map.get(nullifier_hex, None)
            if short_commit:
                commits.append(short_commit)
                self._mark_note_spent(nullifier_hex, short_commit)

        return commits

    def note_summaries(self) -> Iterator[Tuple[int, str, EtherValue]]:
        """
        Returns simple information that can be efficiently read from the notes
        store.
        """
        return self._decode_note_files_in_dir(self.wallet_dir)

    def spent_note_summaries(self) -> Iterator[Tuple[int, str, EtherValue]]:
        """
        Returns simple info from note filenames in the spent directory.
        """
        return self._decode_note_files_in_dir(
            join(self.wallet_dir, SPENT_SUBDIRECTORY))

    def get_next_block(self) -> int:
        return self.state.next_block

    def update_and_save_state(self, next_block: int) -> None:
        self.state.next_block = next_block
        _save_state(self.state_file, self.state)
        self._save_merkle_tree_if_changed()

    def find_note(self, note_id: str) -> ZethNoteDescription:
        note_file = self._find_note_file(note_id)
        if not note_file:
            raise Exception(f"no note with id {note_id}")
        with open(note_file, "r") as note_f:
            return ZethNoteDescription.from_json(note_f.read())

    def _save_merkle_tree_if_changed(self) -> None:
        if self.merkle_tree_changed:
            self.merkle_tree_changed = False
            self.merkle_tree.recompute_root()
            self.merkle_tree.save()

    def _write_note(self, note_desc: ZethNoteDescription) -> None:
        """
        Write a note to the database (currently just a file-per-note).
        """
        note_filename = join(self.wallet_dir, self._note_basename(note_desc))
        with open(note_filename, "w") as note_f:
            note_f.write(note_desc.to_json())

    def _mark_note_spent(self, nullifier_hex: str, short_commit: str) -> None:
        """
        Mark a note as having been spent.  Find the file, move it to the `spent`
        subdirectory, and remove the entry from the `nullifier_map`.
        """
        note_file = self._find_note_file(short_commit)
        if note_file is None:
            raise Exception(f"expected to find file for commit {short_commit}")
        spent_file = \
            join(self.wallet_dir, SPENT_SUBDIRECTORY, basename(note_file))
        move(note_file, spent_file)
        del self.state.nullifier_map[nullifier_hex]

    def _note_basename(self, note_desc: ZethNoteDescription) -> str:
        value_eth = from_zeth_units(int(note_desc.note.value, 16)).ether()
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

    def _decode_note_files_in_dir(
            self, dir_name: str) -> Iterator[Tuple[int, str, EtherValue]]:
        wildcard = join(dir_name, f"note_{self.username}_*")
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


def _check_note(commit: bytes, note: ZethNote) -> bool:
    """
    Recalculate the note commitment and check that it matches `commit`, the
    value emitted by the contract.
    """
    cm = compute_commitment(note)
    if commit != cm:
        print(f"WARN: bad commitment commit={commit.hex()}, cm={cm.hex()}")
        return False
    return True


def _ensure_dir(directory_name: str) -> None:
    if not exists(directory_name):
        makedirs(directory_name)
