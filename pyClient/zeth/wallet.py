from __future__ import annotations
import zeth.joinsplit as joinsplit
from api.util_pb2 import ZethNote
from nacl.public import PrivateKey  # type: ignore
from nacl import encoding  # type: ignore
from os.path import join
from typing import List
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
            ciphertexts: List[bytes],
            k_pk_sender_bytes: bytes) -> List[ZethNote]:
        new_notes_iter = joinsplit.receive_notes(
            ciphertexts, k_pk_sender_bytes, self.k_sk_receiver)
        new_notes = []
        for note in new_notes_iter:
            print(f"[INFO] {self.username} received payment: {note}")
            self._write_note(note)
            new_notes.append(note)
        return new_notes

    def _write_note(self, note: ZethNote) -> None:
        note_filename = join(
            self.wallet_dir,
            f"note_{self.username}_{int(round(time.time() * 1000))}")
        with open(note_filename, "w") as note_f:
            note_f.write(json.dumps(joinsplit.parse_zeth_note(note)))
