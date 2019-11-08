import zeth.joinsplit as joinsplit
import api.util_pb2 as util_pb2
from typing import Tuple, Dict, List


class AddrPk:
    def __init__(self, enc_pk: bytes, a_pk: str):
        self.enc_pk = enc_pk
        self.a_pk = a_pk


class AddrSk:
    def __init__(self, enc_sk: bytes, a_sk: str):
        self.enc_sk = enc_sk
        self.a_sk = a_sk


class KeyEntry:
    def __init__(
            self,
            keypair: joinsplit.ApkAskPair,
            enc_pk: bytes,
            enc_sk: bytes):
        self.addr_pk = AddrPk(enc_pk, keypair.a_pk)
        self.addr_sk = AddrSk(enc_sk, keypair.a_sk)


Keystore = Dict[str, KeyEntry]


def init_test_keystore() -> Keystore:
    """
    Keystore for the tests
    """

    # Alice credentials in the zeth abstraction
    alice_ownership_keys = joinsplit.gen_apk_ask_keypair()
    alice_25519_enc_public_key = \
        b'\x1eO"\n\xdaWnU+\xf5\xaa\x8a#\xd2*\xd3\x11\x9fc\xe52 \xd8^\xbc-' + \
        b'\xb6\xf1\xeej\xf41'
    alice_25519_enc_private_key = \
        b'\xde\xa2\xc1\x0b\xd1\xf7\x13\xf8J\xa4:\xa4\xb6\xfa\xbd\xd5\xc9' + \
        b'\x8a\xd9\xb6\xb4\xc4\xc4I\x88\xa4\xd9\xe2\xee\x9e\x9a\xff'

    # Bob credentials in the zeth abstraction
    bob_ownership_keys = joinsplit.gen_apk_ask_keypair()
    bob_25519_enc_public_key = \
        b't\xc5{5j\xb5\x8a\xd3n\xb3\xab9\xe8s^13\xba\xa2\x91x\xb01(\xf9' + \
        b'\xbb\xf9@r_\x91}'
    bob_25519_enc_private_key = \
        b'\xd3\xf0\x8f ,\x1d#\xdc\xac,\x93\xbd\xd0\xd9\xed\x8c\x92\x822' + \
        b'\xef\xd6\x97^\x86\xf7\xe4/\x85\xb6\x10\xe6o'

    # Charlie credentials in the zeth abstraction
    charlie_ownership_keys = joinsplit.gen_apk_ask_keypair()
    charlie_25519_enc_public_key = \
        b'u\xe7\x88\x9c\xbfE(\xf8\x99\xca<\xa8[<\xa2\x88m\xad\rN"\xf0}' + \
        b'\xec\xfcB\x89\xe6\x96\xcf\x19U'
    charlie_25519_enc_private_key = b'zH\xb66q\x97\x0bO\xcb\xb9q\x9b\xbd-1`I' + \
        b'\xae\x00-\x11\xb9\xed}\x18\x9f\xf6\x8dr\xaa\xd4R'

    return {
        "Alice": KeyEntry(
            alice_ownership_keys,
            alice_25519_enc_public_key,
            alice_25519_enc_private_key),
        "Bob": KeyEntry(
            bob_ownership_keys,
            bob_25519_enc_public_key,
            bob_25519_enc_private_key),
        "Charlie": KeyEntry(
            charlie_ownership_keys,
            charlie_25519_enc_public_key,
            charlie_25519_enc_private_key),
    }


def get_dummy_merkle_path(length: int) -> List[str]:
    mk_path = []
    # Arbitrary sha256 digest used to build the dummy merkle path
    dummy_node = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    for _ in range(length):
        mk_path.append(dummy_node)
    return mk_path


def get_dummy_input(
        recipient_apk: str,
        recipient_ask: str) -> Tuple[util_pb2.ZethNote, str, int]:
    zero_wei_hex = "0000000000000000"
    dummy_note = joinsplit.create_zeth_note(
        joinsplit.NoteRandomness.new(), recipient_apk, zero_wei_hex)
    dummy_note_nullifier = joinsplit.compute_nullifier(dummy_note, recipient_ask)
    dummy_note_address = 7
    return (dummy_note, dummy_note_nullifier, dummy_note_address)
