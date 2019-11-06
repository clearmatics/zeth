import zeth.grpc


def init_test_keystore():
    """
    Keystore for the tests
    """

    # Alice credentials in the zeth abstraction
    alice_ownership_keys = zeth.grpc.gen_apk_ask_keypair()
    alice_25519_enc_public_key = \
        b'\x1eO"\n\xdaWnU+\xf5\xaa\x8a#\xd2*\xd3\x11\x9fc\xe52 \xd8^\xbc-' + \
        b'\xb6\xf1\xeej\xf41'
    alice_25519_enc_private_key = \
        b'\xde\xa2\xc1\x0b\xd1\xf7\x13\xf8J\xa4:\xa4\xb6\xfa\xbd\xd5\xc9' + \
        b'\x8a\xd9\xb6\xb4\xc4\xc4I\x88\xa4\xd9\xe2\xee\x9e\x9a\xff'

    # Bob credentials in the zeth abstraction
    bob_ownership_keys = zeth.grpc.gen_apk_ask_keypair()
    bob_25519_enc_public_key = \
        b't\xc5{5j\xb5\x8a\xd3n\xb3\xab9\xe8s^13\xba\xa2\x91x\xb01(\xf9' + \
        b'\xbb\xf9@r_\x91}'
    bob_25519_enc_private_key = \
        b'\xd3\xf0\x8f ,\x1d#\xdc\xac,\x93\xbd\xd0\xd9\xed\x8c\x92\x822' + \
        b'\xef\xd6\x97^\x86\xf7\xe4/\x85\xb6\x10\xe6o'

    # Charlie credentials in the zeth abstraction
    charlie_ownership_keys = zeth.grpc.gen_apk_ask_keypair()
    charlie_25519_enc_public_key = \
        b'u\xe7\x88\x9c\xbfE(\xf8\x99\xca<\xa8[<\xa2\x88m\xad\rN"\xf0}' + \
        b'\xec\xfcB\x89\xe6\x96\xcf\x19U'
    charlie_25519_enc_private_key = b'zH\xb66q\x97\x0bO\xcb\xb9q\x9b\xbd-1`I' + \
        b'\xae\x00-\x11\xb9\xed}\x18\x9f\xf6\x8dr\xaa\xd4R'

    keystore = {
        "Alice": {
            "addr_pk": {
                "enc_pk": alice_25519_enc_public_key,
                "apk": alice_ownership_keys["apk"]
            },
            "addr_sk": {
                "enc_sk": alice_25519_enc_private_key,
                "ask": alice_ownership_keys["ask"]
            }
        },
        "Bob": {
            "addr_pk": {
                "enc_pk": bob_25519_enc_public_key,
                "apk": bob_ownership_keys["apk"]
            },
            "addr_sk": {
                "enc_sk": bob_25519_enc_private_key,
                "ask": bob_ownership_keys["ask"]
            }
        },
        "Charlie": {
            "addr_pk": {
                "enc_pk": charlie_25519_enc_public_key,
                "apk": charlie_ownership_keys["apk"]
            },
            "addr_sk": {
                "enc_sk": charlie_25519_enc_private_key,
                "ask": charlie_ownership_keys["ask"]
            }
        }
    }
    return keystore


def get_dummy_merkle_path(length):
    mkPath = []
    # Arbitrary sha256 digest used to build the dummy merkle path
    dummyNode = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    for i in range(length):
        mkPath.append(dummyNode)
    return mkPath


def get_dummy_input(recipient_apk, recipient_ask):
    zero_wei_hex = "0000000000000000"
    dummy_note = zeth.grpc.create_zeth_note(zeth.grpc.gen_note_randomness(), recipient_apk, zero_wei_hex)
    dummy_note_nullifier = zeth.grpc.compute_nullifier(dummy_note, recipient_ask)
    dummy_note_address = 7
    return (dummy_note, dummy_note_nullifier, dummy_note_address)
