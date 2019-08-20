import zethGRPC

# Keystore for the tests
def initTestKeystore():
    # Alice credentials in the zeth abstraction
    AliceOwnershipKeys = zethGRPC.generateApkAskKeypair()
    Alice25519PublicKey = b'97aa1d5ffc8322ea87c88de17440ed8feb1ea20e00e6d1a93cafcb2e83da5b0e'
    Alice25519PrivateKey = b'82578283b14d7a3391139957e04aa16fcb498cabf4e8fb85d54a8b2526c28e42'

    # Bob credentials in the zeth abstraction
    BobOwnershipKeys = zethGRPC.generateApkAskKeypair()
    Bob25519PublicKey = b'2cb62682cb3f12bc320c7fa37caf14da344383bc980de3ac43c635237b725b2a'
    Bob25519PrivateKey = b'ec6e45c26de33403c9e4059efdc940939b85f3b340dd95b7a9e32e24601960b6'

    # Charlie credentials in the zeth abstraction
    CharlieOwnershipKeys = zethGRPC.generateApkAskKeypair()
    Charlie25519PublicKey = b'a3058cdc22e4600de1b925ed02743a4310cb3011ec6a953abd9c9b859c9cec6d'
    Charlie25519PrivateKey = b'bce6da6eda2bfe127dc1f3b7406d4f9f36d0747d04daa14b5a296fef54e0f56e'

    keystore = {
        "Alice": {
            "AddrPk": {
                "pubkey": Alice25519PublicKey,
                "aPK": AliceOwnershipKeys["aPK"]
            },
            "AddrSk": {
                "privkey": Alice25519PrivateKey,
                "aSK": AliceOwnershipKeys["aSK"]
            }
        },
        "Bob": {
            "AddrPk": {
                "pubkey": Bob25519PublicKey,
                "aPK": BobOwnershipKeys["aPK"]
            },
            "AddrSk": {
                "privkey": Bob25519PrivateKey,
                "aSK": BobOwnershipKeys["aSK"]
            }
        },
        "Charlie": {
            "AddrPk": {
                "pubkey": Charlie25519PublicKey,
                "aPK": CharlieOwnershipKeys["aPK"]
            },
            "AddrSk": {
                "privkey": Charlie25519PrivateKey,
                "aSK": CharlieOwnershipKeys["aSK"]
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
    dummy_note = zethGRPC.createZethNote(zethGRPC.noteRandomness(), recipient_apk, zero_wei_hex)
    dummy_note_nullifier = zethGRPC.computeNullifier(dummy_note, recipient_ask)
    dummy_note_address = 7
    return (dummy_note, dummy_note_nullifier, dummy_note_address)
