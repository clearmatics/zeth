#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
import zeth.joinsplit as joinsplit
from zeth.contracts import EncryptedNote
from api.util_pb2 import ZethNote
from nacl.public import PrivateKey, PublicKey  # type: ignore
from nacl import encoding  # type: ignore
from os.path import join
from typing import List, Tuple
import time
import json


class Wallet:
    def __init__(self, username: str, wallet_dir: str, k_sk_receiver: PrivateKey):
        self.username = username
        self.wallet_dir = wallet_dir
        self.k_sk_receiver = k_sk_receiver
        self.k_sk_receiver_bytes = \
            k_sk_receiver.encode(encoder=encoding.RawEncoder)

    def receive_notes(
            self,
            addrs_and_ciphertexts: List[EncryptedNote],
            k_pk_sender: PublicKey) -> List[Tuple[int, ZethNote]]:
        new_notes_iter = joinsplit.receive_notes(
            addrs_and_ciphertexts, k_pk_sender, self.k_sk_receiver)
        new_notes = []
        for addr, note in new_notes_iter:
            print(
                f"[INFO] {self.username} received payment: {note} (addr: {addr})")
            self._write_note(note)
            new_notes.append((addr, note))
        return new_notes

    def _write_note(self, note: ZethNote) -> None:
        note_filename = join(
            self.wallet_dir,
            f"note_{self.username}_{int(round(time.time() * 1000))}")
        with open(note_filename, "w") as note_f:
            note_f.write(json.dumps(joinsplit.parse_zeth_note(note)))
