import zeth.joinsplit as joinsplit


def initTestKeystore():
    """
    Keystore for the tests
    """

    # Alice credentials in the zeth abstraction
    AliceOwnershipKeys = joinsplit.generateApkAskPair()
    Alice25519EncPublicKey = \
        b'\x1eO"\n\xdaWnU+\xf5\xaa\x8a#\xd2*\xd3\x11\x9fc\xe52 \xd8^\xbc-' + \
        b'\xb6\xf1\xeej\xf41'
    Alice25519EncPrivateKey = \
        b'\xde\xa2\xc1\x0b\xd1\xf7\x13\xf8J\xa4:\xa4\xb6\xfa\xbd\xd5\xc9' + \
        b'\x8a\xd9\xb6\xb4\xc4\xc4I\x88\xa4\xd9\xe2\xee\x9e\x9a\xff'

    # Bob credentials in the zeth abstraction
    BobOwnershipKeys = joinsplit.generateApkAskPair()
    Bob25519EncPublicKey = \
        b't\xc5{5j\xb5\x8a\xd3n\xb3\xab9\xe8s^13\xba\xa2\x91x\xb01(\xf9' + \
        b'\xbb\xf9@r_\x91}'
    Bob25519EncPrivateKey = \
        b'\xd3\xf0\x8f ,\x1d#\xdc\xac,\x93\xbd\xd0\xd9\xed\x8c\x92\x822' + \
        b'\xef\xd6\x97^\x86\xf7\xe4/\x85\xb6\x10\xe6o'

    # Charlie credentials in the zeth abstraction
    CharlieOwnershipKeys = joinsplit.generateApkAskPair()
    Charlie25519EncPublicKey = \
        b'u\xe7\x88\x9c\xbfE(\xf8\x99\xca<\xa8[<\xa2\x88m\xad\rN"\xf0}' + \
        b'\xec\xfcB\x89\xe6\x96\xcf\x19U'
    Charlie25519EncPrivateKey = b'zH\xb66q\x97\x0bO\xcb\xb9q\x9b\xbd-1`I' + \
        b'\xae\x00-\x11\xb9\xed}\x18\x9f\xf6\x8dr\xaa\xd4R'

    keystore = {
        "Alice": {
            "AddrPk": {
                "encPK": Alice25519EncPublicKey,
                "aPK": AliceOwnershipKeys.aPK
            },
            "AddrSk": {
                "encSK": Alice25519EncPrivateKey,
                "aSK": AliceOwnershipKeys.aSK
            }
        },
        "Bob": {
            "AddrPk": {
                "encPK": Bob25519EncPublicKey,
                "aPK": BobOwnershipKeys.aPK
            },
            "AddrSk": {
                "encSK": Bob25519EncPrivateKey,
                "aSK": BobOwnershipKeys.aSK
            }
        },
        "Charlie": {
            "AddrPk": {
                "encPK": Charlie25519EncPublicKey,
                "aPK": CharlieOwnershipKeys.aPK
            },
            "AddrSk": {
                "encSK": Charlie25519EncPrivateKey,
                "aSK": CharlieOwnershipKeys.aSK
            }
        }
    }
    return keystore


def getDummyMerklePath(length):
    mkPath = []
    # Arbitrary sha256 digest used to build the dummy merkle path
    dummyNode = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    for i in range(length):
        mkPath.append(dummyNode)
    return mkPath


def getDummyInput(recipient_apk, recipient_ask):
    zero_wei_hex = "0000000000000000"
    dummy_note = joinsplit.createZethNote(
        joinsplit.noteRandomness(), recipient_apk, zero_wei_hex)
    dummy_note_nullifier = joinsplit.computeNullifier(dummy_note, recipient_ask)
    dummy_note_address = 7
    return (dummy_note, dummy_note_nullifier, dummy_note_address)
