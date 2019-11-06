from __future__ import annotations
import zeth.constants as constants
import zeth.errors as errors
from zeth.utils import get_trusted_setup_dir, hex_extend_32bytes, \
    hex_digest_to_binary_string, string_list_flatten, encode_single, \
    encode_abi, encrypt, decrypt, get_public_key_from_bytes
from zeth.prover_client import ProverClient
# import api.util_pb2 as util_pb2
from api.util_pb2 import ZethNote, JSInput, HexadecimalPointBaseGroup1Affine, \
    HexadecimalPointBaseGroup2Affine
from nacl.public import PrivateKey, PublicKey  # type: ignore
import nacl.utils  # type: ignore
import api.prover_pb2 as prover_pb2

import os
import json
import sys
from Crypto import Random
from hashlib import blake2s, sha256
from py_ecc import bn128 as ec
from typing import Tuple, Dict, List, Iterable, Union, Any


FQ = ec.FQ
G1 = Tuple[ec.FQ, ec.FQ]


class ApkAskPair(object):
    def __init__(self, aSK: str, aPK: str):
        self.aPK = aPK
        self.aSK = aSK


SK = Tuple[int, int]
VK = Tuple[G1, G1]


class VkSkPair(object):
    def __init__(self, x: int, y: int, x_g1: G1, y_g1: G1):
        self.vk = (x_g1, y_g1)
        self.sk = (x, y)


# Dictionary representing a VerificationKey from any supported snark
GenericVerificationKey = Dict[str, Any]


# Dictionary representing a Proof from any supported snark
GenericProof = Dict[str, Any]


# class ZkSnarkProvider(object):
#     def parseVerificationKey(
#             vkObj: prover_pb2.VerificationKey) -> GenericVerificationKey:
#         pass

#     def writeVerificationKey(
#         vkObj: prover_pb2.VerificationKey) -> None:
#         pass

#     def parseProof(
#         proofObj: prover_pb2.ExtendedProof) -> GenericProof:
#         pass

#     def deploy_verifier_contract(
#             vk: prover_pb2.VerificationKey,
#             deployer_address,
#     ) -> str:
#         """
#         Return address of verifier contract
#         """
#         pass

#     def deploy mixer_contract() -> Tuple[Instance]:
#         pass

#     def encode_and_hash_for_contract(
#             proof: GenericProof) ->
#     {
#         proof_digest: bytes,
#         inputs_digest: bytes,
#         contract_input: ContractProof
#         }

#     def call_mixer(
#             mixer_instance: Any,
#             ...
#             proof: ContractProof,
#             ...
#             other params from mix_groth16...)

#     #   - hash_proof, hash_inputs for signing


class NoteRandomness(object):
    def __init__(self, rho: str, trapR: str):
        self.rho = rho
        self.trapR = trapR

    @staticmethod
    def new() -> NoteRandomness:
        """
        Compute the note randomness: the trapdoor trapR and rho. Starting the
        Non-Malleability update, rho is computed from phi (see above), the rho
        generated in this function is thus obsolete except for dummy input
        notes.
        """
        rho = bytes(Random.get_random_bytes(32)).hex()
        trapR = bytes(Random.get_random_bytes(48)).hex()
        return NoteRandomness(rho, trapR)


def createZethNote(
        randomness: NoteRandomness,
        recipientApk: str,
        value: str) -> ZethNote:
    """
    We follow the formatting of the proto file. Create a ZethNote description
    Starting the Non-Malleability update, this function is used only for dummy
    input notes as rhoS are now structured ( rho = PRF_{phi}(i, phi, h_sig) ).
    """
    note = ZethNote(
        aPK=recipientApk,
        value=value,
        rho=randomness.rho,
        trapR=randomness.trapR
    )
    return note


def createZethNotes(
        phi: str,
        hsig: str,
        recipientApk0: str,
        value0: str,
        recipientApk1: str,
        value1: str) -> Tuple[ZethNote, ZethNote]:
    """
    Create two ordered ZethNotes. This function is used to generate new output
    notes.
    """
    rho0 = computeRhoi(phi, hsig, 0)
    randomness0 = NoteRandomness.new()
    note0 = ZethNote(
        aPK=recipientApk0,
        value=value0,
        rho=rho0,
        trapR=randomness0.trapR
    )

    rho1 = computeRhoi(phi, hsig, 1)
    randomness1 = NoteRandomness.new()
    note1 = ZethNote(
        aPK=recipientApk1,
        value=value1,
        rho=rho1,
        trapR=randomness1.trapR
    )

    return note0, note1


def parseZethNote(zethNoteGRPCObj: ZethNote) -> Dict[str, str]:
    noteJSON = {
        "aPK": zethNoteGRPCObj.aPK,
        "value": zethNoteGRPCObj.value,
        "rho": zethNoteGRPCObj.rho,
        "trapR": zethNoteGRPCObj.trapR,
    }
    return noteJSON


def zethNoteObjFromParsed(parsedZethNote: Dict[str, str]) -> ZethNote:
    note = ZethNote(
        aPK=parsedZethNote["aPK"],
        value=parsedZethNote["value"],
        rho=parsedZethNote["rho"],
        trapR=parsedZethNote["trapR"]
    )
    return note


def computeCommitment(zethNoteGRPCObj: ZethNote) -> str:
    """
    Used by the recipient of a payment to recompute the commitment and check
    the membership in the tree to confirm the validity of a payment
    """
    # inner_k = blake2s(a_pk || rho)
    inner_k = blake2s(
        encode_abi(
            ['bytes32', 'bytes32'],
            [bytes.fromhex(zethNoteGRPCObj.aPK),
             bytes.fromhex(zethNoteGRPCObj.rho)])
    ).hexdigest()

    # outer_k = blake2s(r || [inner_k]_128)
    first128InnerComm = inner_k[0:128]
    outer_k = blake2s(
        encode_abi(
            ['bytes', 'bytes'],
            [bytes.fromhex(zethNoteGRPCObj.trapR),
             bytes.fromhex(first128InnerComm)])).hexdigest()

    # cm = blake2s(outer_k || 0^192 || value_v)
    frontPad = "000000000000000000000000000000000000000000000000"
    cm = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            [bytes.fromhex(outer_k),
             bytes.fromhex(frontPad + zethNoteGRPCObj.value)])
    ).hexdigest()
    return cm


def computeNullifier(zethNote: ZethNote, spendingAuthAsk: str) -> str:
    """
    Returns nf = blake2s(1110 || [a_sk]_252 || rho)
    """
    binaryAsk = hex_digest_to_binary_string(spendingAuthAsk)
    first252Ask = binaryAsk[:252]
    leftLegBin = "1110" + first252Ask
    leftLegHex = "{0:0>4X}".format(int(leftLegBin, 2))
    nullifier = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            [bytes.fromhex(leftLegHex), bytes.fromhex(zethNote.rho)])
    ).hexdigest()
    return nullifier


def computeRhoi(phi: str, hsig: str, i: int) -> str:
    """
    Returns rho_i = blake2s(0 || i || 10 || [phi]_252 || hsig)
    See: Zcash protocol spec p. 57, Section 5.4.2 Pseudo Random Functions
    """

    # [SANITY CHECK] make sure i is in the interval [0, 1]
    # Since we only allow for 2 input notes in the joinsplit
    assert(i < constants.JS_INPUTS)

    # Append PRF^{rho} tag to a_sk
    binaryPhi = hex_digest_to_binary_string(phi)
    first252Phi = binaryPhi[:252]
    leftLegBin = "0" + str(i) + "10" + first252Phi
    leftLegHex = "{0:0>4X}".format(int(leftLegBin, 2))

    rho_i = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            [bytes.fromhex(leftLegHex), bytes.fromhex(hsig)])
    ).hexdigest()
    return rho_i


def deriveAPK(ask: str) -> str:
    """
    Returns a_pk = blake2s(1100 || [a_sk]_252 || 0^256)
    """
    binaryAsk = hex_digest_to_binary_string(ask)
    first252Ask = binaryAsk[:252]
    leftLegBin = "1100" + first252Ask
    leftLegHex = "{0:0>4X}".format(int(leftLegBin, 2))
    zeroes = "0000000000000000000000000000000000000000000000000000000000000000"
    a_pk = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            [bytes.fromhex(leftLegHex), bytes.fromhex(zeroes)])
    ).hexdigest()
    return a_pk


def generateApkAskPair() -> ApkAskPair:
    a_sk = bytes(Random.get_random_bytes(32)).hex()
    a_pk = deriveAPK(a_sk)
    keypair = ApkAskPair(a_sk, a_pk)
    return keypair


def createJSInput(
        merklePath: List[str],
        address: int,
        note: ZethNote,
        ask: str,
        nullifier: str) -> JSInput:
    jsInput = JSInput(
        merkleNode=merklePath,
        address=address,
        note=note,
        spendingASK=ask,
        nullifier=nullifier
    )
    return jsInput


def generateOTSchnorrVkSkpair() -> VkSkPair:
    x = int(bytes(Random.get_random_bytes(32)).hex(), 16) % constants.ZETH_PRIME
    X = ec.multiply(ec.G1, x)
    y = int(bytes(Random.get_random_bytes(32)).hex(), 16) % constants.ZETH_PRIME
    Y = ec.multiply(ec.G1, y)
    return VkSkPair(x, y, X, Y)


def encodeInputToHash(message_list: List[Union[str, List[str]]]) -> bytes:
    """
    Encode the primary inputs as defined in ZCash chapter 4.15.1 into a byte
    array (https://github.com/zcash/zips/blob/master/protocol/protocol.pdf) The
    root, nullifierS, commitmentS, h_sig and h_iS are encoded over two field
    elements The public values are encoded over one field element
    """
    input_sha = bytearray()

    # Flatten the input list
    messages = string_list_flatten(message_list)

    # Encode the given Merkle Tree root
    root = hex_extend_32bytes(messages[0][2:])
    root_encoded = encode_single("bytes32", bytes.fromhex(root))
    input_sha += root_encoded

    # Encode the given input nullifiers
    for i in range(1, 1 + 2*(constants.JS_INPUTS), 2):
        nf = _fields_to_hex(messages[i], messages[i+1])
        nf_encoded = encode_single("bytes32", bytes.fromhex(nf))
        input_sha += nf_encoded

    # Encode the given output commitments
    for i in range(1 + 2*(constants.JS_INPUTS), 1 + 2*(constants.JS_INPUTS + constants.JS_OUTPUTS), 2):
        cm = _fields_to_hex(messages[i], messages[i+1])
        cm_encoded = encode_single("bytes32", bytes.fromhex(cm))
        input_sha += cm_encoded

    # Encode the public value in
    v_in = messages[1 + 2*(constants.JS_INPUTS + constants.JS_OUTPUTS)][2:]
    v_in = hex_extend_32bytes(v_in)
    vin_encoded = encode_single("bytes32", bytes.fromhex(v_in))
    input_sha += vin_encoded

    # Encode the public value out
    v_out = messages[1 + 2*(constants.JS_INPUTS + constants.JS_OUTPUTS) + 1][2:]
    v_out = hex_extend_32bytes(v_out)
    vout_encoded = encode_single("bytes32", bytes.fromhex(v_out))
    input_sha += vout_encoded

    # Encode the h_sig
    hsig = _fields_to_hex(
        messages[1 + 2*(constants.JS_INPUTS + constants.JS_OUTPUTS) + 1 + 1],
        messages[1 + 2*(constants.JS_INPUTS + constants.JS_OUTPUTS) + 1 + 1 + 1])
    hsig_encoded = encode_single("bytes32", bytes.fromhex(hsig))
    input_sha += hsig_encoded

    # Encode the h_iS
    for i in range(
        1 + 2*(constants.JS_INPUTS + constants.JS_OUTPUTS + 1 + 1),
        1 + 2*(constants.JS_INPUTS + constants.JS_OUTPUTS + 1 + 1 +
               constants.JS_INPUTS),
        2
    ):
        hi = _fields_to_hex(messages[i], messages[i+1])
        hi_encoded = encode_single("bytes32", bytes.fromhex(hi))
        input_sha += hi_encoded

    return input_sha


def _fields_to_hex(longfield: str, shortfield: str) -> str:
    """
    Encode a 256 bit array written over two field elements into a single 32
    byte long hex

    if A= x0 ... x255 and B = y0 ... y7, returns R = hex(x255 ... x3 || y7 y6 y5)
    """
    # Convert longfield into a 253 bit long array
    long_bit = "{0:b}".format(int(longfield, 16))
    if len(long_bit) > 253:
        long_bit = long_bit[:253]
    long_bit = "0"*(253-len(long_bit)) + long_bit

    # Convert shortfield into a 3 bit long array
    short_bit = "{0:b}".format(int(shortfield, 16))
    if len(short_bit) < 3:
        short_bit = "0"*(3-len(short_bit)) + short_bit

    # Reverse the bit arrays
    reversed_long = long_bit[::-1]
    reversed_short = short_bit[::-1]

    # Fill the result 256 bit long array
    res = reversed_long[:253]
    res += reversed_short[:3]
    res = hex_extend_32bytes("{0:0>4X}".format(int(res, 2)))

    return res


def sign(
        keypair: VkSkPair,
        hash_ciphers: str,
        hash_proof: str,
        hash_inputs: str) -> int:
    """
    Generate a Schnorr one-time signature of the ciphertexts, proofs and
    primary inputs We chose to sign the hash of the proof for modularity (to
    use the same code regardless of whether GROTH16 or PGHR13 proof system is
    chosen), and sign the hash of the ciphers and inputs for consistency.
    """
    # Parse the signature key pair
    vk = keypair.vk
    sk = keypair.sk

    # Format part of the public key as an hex
    y0_hex = hex_extend_32bytes("{0:0>4X}".format(int(vk[1][0])))
    y1_hex = hex_extend_32bytes("{0:0>4X}".format(int(vk[1][1])))

    # Encode and hash the verifying key and input hashes
    data_to_sign = encode_abi(
        ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
        [
            bytes.fromhex(y0_hex),
            bytes.fromhex(y1_hex),
            bytes.fromhex(hash_ciphers),
            bytes.fromhex(hash_proof),
            bytes.fromhex(hash_inputs)
        ]
    )
    data_hex = sha256(data_to_sign).hexdigest()

    # Convert the hex digest into a field element
    h = int(data_hex, 16) % constants.ZETH_PRIME

    # Compute the signature sigma
    sigma = sk[1] + h * sk[0] % constants.ZETH_PRIME

    return sigma


def parseVerificationKeyPGHR13(
        vkObj: prover_pb2.VerificationKey) -> GenericVerificationKey:
    vkJSON: GenericVerificationKey = {}
    vkJSON["a"] = _parseHexPointBaseGroup2Affine(
        vkObj.r1csPpzksnarkVerificationKey.a)
    vkJSON["b"] = _parseHexPointBaseGroup1Affine(
        vkObj.r1csPpzksnarkVerificationKey.b)
    vkJSON["c"] = _parseHexPointBaseGroup2Affine(
        vkObj.r1csPpzksnarkVerificationKey.c)
    vkJSON["g"] = _parseHexPointBaseGroup2Affine(
        vkObj.r1csPpzksnarkVerificationKey.g)
    vkJSON["gb1"] = _parseHexPointBaseGroup1Affine(
        vkObj.r1csPpzksnarkVerificationKey.gb1)
    vkJSON["gb2"] = _parseHexPointBaseGroup2Affine(
        vkObj.r1csPpzksnarkVerificationKey.gb2)
    vkJSON["z"] = _parseHexPointBaseGroup2Affine(
        vkObj.r1csPpzksnarkVerificationKey.z)
    vkJSON["IC"] = json.loads(vkObj.r1csPpzksnarkVerificationKey.IC)
    return vkJSON


def parseVerificationKeyGROTH16(
        vkObj: prover_pb2.VerificationKey) -> GenericVerificationKey:
    vkJSON: GenericVerificationKey = {}
    vkJSON["alpha_g1"] = _parseHexPointBaseGroup1Affine(
        vkObj.r1csGgPpzksnarkVerificationKey.alpha_g1)
    vkJSON["beta_g2"] = _parseHexPointBaseGroup2Affine(
        vkObj.r1csGgPpzksnarkVerificationKey.beta_g2)
    vkJSON["delta_g2"] = _parseHexPointBaseGroup2Affine(
        vkObj.r1csGgPpzksnarkVerificationKey.delta_g2)
    vkJSON["abc_g1"] = json.loads(vkObj.r1csGgPpzksnarkVerificationKey.abc_g1)
    return vkJSON


def parseVerificationKey(
        vkObj: prover_pb2.VerificationKey,
        zksnark: str) -> GenericVerificationKey:
    if zksnark == constants.PGHR13_ZKSNARK:
        return parseVerificationKeyPGHR13(vkObj)
    elif zksnark == constants.GROTH16_ZKSNARK:
        return parseVerificationKeyGROTH16(vkObj)
    else:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)


def writeVerificationKey(
        vkObj: prover_pb2.VerificationKey,
        zksnark: str) -> None:
    """
    Writes the verification key (object) in a json file
    """
    vkJSON = parseVerificationKey(vkObj, zksnark)
    setupDir = get_trusted_setup_dir()
    filename = os.path.join(setupDir, "vk.json")
    with open(filename, 'w') as outfile:
        json.dump(vkJSON, outfile)


def parseProofPGHR13(proofObj: prover_pb2.ExtendedProof) -> GenericProof:
    proofJSON: GenericProof = {}
    proofJSON["a"] = _parseHexPointBaseGroup1Affine(
        proofObj.r1csPpzksnarkExtendedProof.a)
    proofJSON["a_p"] = _parseHexPointBaseGroup1Affine(
        proofObj.r1csPpzksnarkExtendedProof.aP)
    proofJSON["b"] = _parseHexPointBaseGroup2Affine(
        proofObj.r1csPpzksnarkExtendedProof.b)
    proofJSON["b_p"] = _parseHexPointBaseGroup1Affine(
        proofObj.r1csPpzksnarkExtendedProof.bP)
    proofJSON["c"] = _parseHexPointBaseGroup1Affine(
        proofObj.r1csPpzksnarkExtendedProof.c)
    proofJSON["c_p"] = _parseHexPointBaseGroup1Affine(
        proofObj.r1csPpzksnarkExtendedProof.cP)
    proofJSON["h"] = _parseHexPointBaseGroup1Affine(
        proofObj.r1csPpzksnarkExtendedProof.h)
    proofJSON["k"] = _parseHexPointBaseGroup1Affine(
        proofObj.r1csPpzksnarkExtendedProof.k)
    proofJSON["inputs"] = json.loads(proofObj.r1csPpzksnarkExtendedProof.inputs)
    return proofJSON


def parseProofGROTH16(proofObj: prover_pb2.ExtendedProof) -> GenericProof:
    proofJSON: GenericProof = {}
    proofJSON["a"] = _parseHexPointBaseGroup1Affine(
        proofObj.r1csGgPpzksnarkExtendedProof.a)
    proofJSON["b"] = _parseHexPointBaseGroup2Affine(
        proofObj.r1csGgPpzksnarkExtendedProof.b)
    proofJSON["c"] = _parseHexPointBaseGroup1Affine(
        proofObj.r1csGgPpzksnarkExtendedProof.c)
    proofJSON["inputs"] = json.loads(proofObj.r1csGgPpzksnarkExtendedProof.inputs)
    return proofJSON


def parseProof(
        proofObj: prover_pb2.ExtendedProof,
        zksnark: str) -> GenericProof:
    if zksnark == constants.PGHR13_ZKSNARK:
        return parseProofPGHR13(proofObj)
    elif zksnark == constants.GROTH16_ZKSNARK:
        return parseProofGROTH16(proofObj)
    else:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)


def compute_joinsplit2x2_inputs(
        mk_root: str,
        input_note0: ZethNote,
        input_address0: int,
        mk_path0: List[str],
        input_note1: ZethNote,
        input_address1: int,
        mk_path1: List[str],
        sender_ask: str,
        recipient0_apk: str,
        recipient1_apk: str,
        output_note_value0: str,
        output_note_value1: str,
        public_in_value: str,
        public_out_value: str,
        joinsplit_vk: VK) -> prover_pb2.ProofInputs:
    """
    Create a ProofInput object for joinsplit parameters
    """
    input_nullifier0 = computeNullifier(input_note0, sender_ask)
    input_nullifier1 = computeNullifier(input_note1, sender_ask)
    js_inputs = [
        createJSInput(
            mk_path0, input_address0, input_note0, sender_ask, input_nullifier0),
        createJSInput(
            mk_path1, input_address1, input_note1, sender_ask, input_nullifier1)
    ]

    randomSeed = _signatureRandomness()
    h_sig = _computeHSig(
        randomSeed,
        input_nullifier0,
        input_nullifier1,
        joinsplit_vk)
    phi = _transactionRandomness()

    output_note0, output_note1 = createZethNotes(
        phi,
        h_sig,
        recipient0_apk,
        output_note_value0,
        recipient1_apk,
        output_note_value1
    )

    js_outputs = [
        output_note0,
        output_note1
    ]

    return prover_pb2.ProofInputs(
        root=mk_root,
        jsInputs=js_inputs,
        jsOutputs=js_outputs,
        inPubValue=public_in_value,
        outPubValue=public_out_value,
        hSig=h_sig,
        phi=phi)


def getProofJoinsplit2By2(
        prover_client: ProverClient,
        mk_root: str,
        input_note0: ZethNote,
        input_address0: int,
        mk_path0: List[str],
        input_note1: ZethNote,
        input_address1: int,
        mk_path1: List[str],
        sender_ask: str,
        recipient0_apk: str,
        recipient1_apk: str,
        output_note_value0: str,
        output_note_value1: str,
        public_in_value: str,
        public_out_value: str,
        zksnark: str) -> Tuple[ZethNote, ZethNote, Dict[str, Any], VkSkPair]:
    """
    Query the prover server to generate a proof for the given joinsplit
    parameters.
    """
    joinsplit_keypair = generateOTSchnorrVkSkpair()
    proof_input = compute_joinsplit2x2_inputs(
        mk_root,
        input_note0,
        input_address0,
        mk_path0,
        input_note1,
        input_address1,
        mk_path1,
        sender_ask,
        recipient0_apk,
        recipient1_apk,
        output_note_value0,
        output_note_value1,
        public_in_value,
        public_out_value,
        joinsplit_keypair.vk)
    proof_obj = prover_client.get_proof(proof_input)
    proof_json = parseProof(proof_obj, zksnark)

    # We return the zeth notes to be able to spend them later
    # and the proof used to create them
    return (
        proof_input.jsOutputs[0],
        proof_input.jsOutputs[1],
        proof_json,
        joinsplit_keypair)


def encrypt_notes(
        notes: List[Tuple[ZethNote, PublicKey]]) -> Tuple[bytes, List[bytes]]:
    """
    Encrypts a set of output notes to be decrypted by the respective receivers.
    Returns the senders (ephemeral) public key (encoded as bytes) and the
    ciphertexts corresponding to each note.
    """
    # generate ephemeral ec25519 key
    eph_sk = PrivateKey.generate()

    def _encrypt_note(out_note: ZethNote, pk: PublicKey) -> bytes:
        out_note_str = json.dumps(parseZethNote(out_note))
        return encrypt(out_note_str, pk, eph_sk)

    pk_sender = eph_sk.public_key.encode(encoder=nacl.encoding.RawEncoder)
    ciphertexts = [_encrypt_note(note, pk) for (note, pk) in notes]
    return (pk_sender, ciphertexts)


def receive_notes(
        ciphertexts: List[bytes],
        pk_sender_enc: bytes,
        sk_receiver: PrivateKey) -> Iterable[ZethNote]:
    """
    Given the receivers secret key, and the event data from a transaction
    (encrypted notes), decrypt any that are intended for the receiver.
    """
    pk_sender: PublicKey = get_public_key_from_bytes(pk_sender_enc)

    for ciphertext in ciphertexts:
        try:
            plaintext = decrypt(ciphertext, pk_sender, sk_receiver)
            yield zethNoteObjFromParsed(json.loads(plaintext))
        except Exception as e:
            print(f"receive_notes: error: {e}")
            continue


def _computeHSig(randomSeed: bytes, nf0: str, nf1: str, joinSplitPubKey: VK) -> str:
    """
    Compute h_sig = blake2s(randomSeed, nf0, nf1, joinSplitPubKey)
    Flatten the verification key
    """
    JSPubKeyHex = [item for sublist in joinSplitPubKey for item in sublist]

    vk_hex = ""
    for item in JSPubKeyHex:
        # For each element of the list, convert it to an hex and append it
        vk_hex += hex_extend_32bytes("{0:0>4X}".format(int(item)))

    h_sig = blake2s(
        encode_abi(
            ['bytes32', 'bytes32', 'bytes32', 'bytes'],
            [
                randomSeed,
                bytes.fromhex(nf0),
                bytes.fromhex(nf1),
                bytes.fromhex(vk_hex)
            ]
        )
    ).hexdigest()

    return h_sig


def _signatureRandomness() -> bytes:
    """
    Compute the signature randomness "randomSeed", used for computing h_sig
    """
    randomSeed = bytes(Random.get_random_bytes(32))
    return randomSeed


def _transactionRandomness() -> str:
    """
    Compute the transaction randomness "phi", used for computing the new rhoS
    """
    rand_phi = bytes(Random.get_random_bytes(32)).hex()
    return rand_phi


def _parseHexPointBaseGroup1Affine(
        point: HexadecimalPointBaseGroup1Affine) -> Tuple[str, str]:
    return (point.xCoord, point.yCoord)


def _parseHexPointBaseGroup2Affine(
        point: HexadecimalPointBaseGroup2Affine
) -> Tuple[Tuple[str, str], Tuple[str, str]]:
    return (
        (point.xC1Coord, point.xC0Coord),
        (point.yC1Coord, point.yC0Coord)
    )
