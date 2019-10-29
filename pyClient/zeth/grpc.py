from Crypto import Random
import os
import json
import sys

# Access the encoding and hash functions
from eth_abi import encode_single, encode_abi
from hashlib import blake2s, sha256

# Access the gRPC service and the proto messages
import grpc
from google.protobuf import empty_pb2
import api.util_pb2 as util_pb2  # type: ignore
import api.prover_pb2 as prover_pb2  # type: ignore
import api.prover_pb2_grpc as prover_pb2_grpc  # type: ignore

import zeth.constants as constants
import zeth.errors as errors
from zeth.utils import get_trusted_setup_dir

# Import elliptic curve operations
from py_ecc import bn128 as ec


def getVerificationKey(grpcEndpoint):
    """
    Fetch the verification key from the proving service
    """
    with grpc.insecure_channel(grpcEndpoint) as channel:
        stub = prover_pb2_grpc.ProverStub(channel)
        print("-------------- Get the verification key --------------")
        verificationkey = stub.GetVerificationKey(makeEmptyMessage())
        return verificationkey


def getProof(grpcEndpoint, proofInputs):
    """
    Request a proof generation to the proving service
    """
    with grpc.insecure_channel(grpcEndpoint) as channel:
        stub = prover_pb2_grpc.ProverStub(channel)
        print("-------------- Get the proof --------------")
        proof = stub.Prove(proofInputs)
        return proof


def hex2int(elements):
    ints = []
    for el in elements:
        ints.append(int(el, 16))
    return(ints)


def hex32bytes(element):
    res = str(element)
    if len(res) % 2 != 0:
        res = "0" + res
    res = "00"*int((64-len(res))/2) + res
    return res


def computeHSig(randomSeed, nf0, nf1, joinSplitPubKey):
    """
    Compute h_sig = blake2s(randomSeed, nf0, nf1, joinSplitPubKey)
    Flatten the verification key
    """
    JSPubKeyHex = [item for sublist in joinSplitPubKey for item in sublist]

    vk_hex = ""
    for item in JSPubKeyHex:
        # For each element of the list, convert it to an hex and append it
        vk_hex += hex32bytes("{0:0>4X}".format(int(item)))

    h_sig = blake2s(
        encode_abi(
            ['bytes32', 'bytes32', 'bytes32', 'bytes'],
            (
                bytes.fromhex(randomSeed),
                bytes.fromhex(nf0),
                bytes.fromhex(nf1),
                bytes.fromhex(vk_hex)
            )
        )
    ).hexdigest()

    return h_sig


def signatureRandomness():
    """
    Compute the signature randomness "randomSeed", used for computing h_sig
    """
    randomSeed = bytes(Random.get_random_bytes(32)).hex()
    return randomSeed


def transactionRandomness():
    """
    Compute the transaction randomness "phi", used for computing the new rhoS
    """
    rand_phi = bytes(Random.get_random_bytes(32)).hex()
    return rand_phi


def noteRandomness():
    """
    Compute the note randomness: the trapdoor trapR and rho. Starting the
    Non-Malleability update, rho is computed from phi (see above), the rho
    generated in this function is thus obsolete except for dummy input notes.
    """
    rand_rho = bytes(Random.get_random_bytes(32)).hex()
    rand_trapR = bytes(Random.get_random_bytes(48)).hex()
    randomness = {
        "rho": rand_rho,
        "trapR": rand_trapR
    }
    return randomness


def createZethNote(randomness, recipientApk, value):
    """
    We follow the formatting of the proto file.  Create a ZethNote description
    Starting the Non-Malleability update, this function is used only for dummy
    input notes as rhoS are now structured ( rho = PRF_{phi}(i, phi, h_sig) ).
    """
    note = util_pb2.ZethNote(
        aPK=recipientApk,
        value=value,
        rho=randomness["rho"],
        trapR=randomness["trapR"]
    )
    return note


def createZethNotes(phi, hsig, recipientApk0, value0, recipientApk1, value1):
    """
    Create two ordered ZethNotes.  This function is used to generate new output
    notes.
    """
    rho0 = computeRhoi(phi, hsig, 0)
    randomness0 = noteRandomness()
    note0 = util_pb2.ZethNote(
        aPK=recipientApk0,
        value=value0,
        rho=rho0,
        trapR=randomness0["trapR"]
    )

    rho1 = computeRhoi(phi, hsig, 1)
    randomness1 = noteRandomness()
    note1 = util_pb2.ZethNote(
        aPK=recipientApk1,
        value=value1,
        rho=rho1,
        trapR=randomness1["trapR"]
    )

    return note0, note1


def parseZethNote(zethNoteGRPCObj):
    noteJSON = {
        "aPK": zethNoteGRPCObj.aPK,
        "value": zethNoteGRPCObj.value,
        "rho": zethNoteGRPCObj.rho,
        "trapR": zethNoteGRPCObj.trapR,
    }
    return noteJSON


def zethNoteObjFromParsed(parsedZethNote):
    note = util_pb2.ZethNote(
        aPK=parsedZethNote["aPK"],
        value=parsedZethNote["value"],
        rho=parsedZethNote["rho"],
        trapR=parsedZethNote["trapR"]
    )
    return note


def hexFmt(string):
    return "0x" + string


def computeCommitment(zethNoteGRPCObj):
    """
    Used by the recipient of a payment to recompute the commitment and check
    the membership in the tree to confirm the validity of a payment
    """
    # inner_k = blake2s(a_pk || rho)
    inner_k = blake2s(
        encode_abi(
            ['bytes32', 'bytes32'],
            (bytes.fromhex(zethNoteGRPCObj.aPK),
             bytes.fromhex(zethNoteGRPCObj.rho)))
    ).hexdigest()

    # outer_k = blake2s(r || [inner_k]_128)
    first128InnerComm = inner_k[0:128]
    outer_k = blake2s(
        encode_abi(
            ['bytes', 'bytes'],
            (bytes.fromhex(zethNoteGRPCObj.trapR),
             bytes.fromhex(first128InnerComm)))).hexdigest()

    # cm = blake2s(outer_k || 0^192 || value_v)
    frontPad = "000000000000000000000000000000000000000000000000"
    cm = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            (bytes.fromhex(outer_k),
             bytes.fromhex(frontPad + zethNoteGRPCObj.value)))
    ).hexdigest()
    return cm


def hexadecimalDigestToBinaryString(digest):
    def binary(x):
        zipped = zip(
            *[["{0:04b}".format(int(c, 16)) for c in reversed("0"+x)][n::2]
              for n in [1, 0]])
        return "".join(reversed(
            [i+j for i, j in zipped]))
    return binary(digest)


def computeNullifier(zethNote, spendingAuthAsk):
    """
    Returns nf = blake2s(1110 || [a_sk]_252 || rho)
    """
    binaryAsk = hexadecimalDigestToBinaryString(spendingAuthAsk)
    first252Ask = binaryAsk[:252]
    leftLegBin = "1110" + first252Ask
    leftLegHex = "{0:0>4X}".format(int(leftLegBin, 2))
    nullifier = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            (bytes.fromhex(leftLegHex), bytes.fromhex(zethNote.rho)))
    ).hexdigest()
    return nullifier


def computeHi(ask, hsig, i):
    """
    Returns h_i = blake2s(0 || i || 00 || [a_sk]_252 || hsig)
    See: Zcash protocol spec p. 57, Section 5.4.2 Pseudo Random Functions
    """

    # [SANITY CHECK] make sure i is in the interval [0, 1]
    # Since we only allow for 2 input notes in the joinsplit
    if i not in [0, 1]:
        return -1

    # Append PRF^{pk} tag to a_sk
    binaryAsk = hexadecimalDigestToBinaryString(ask)
    first252Ask = binaryAsk[:252]
    leftLegBin = "0" + str(i) + "00" + first252Ask
    leftLegHex = "{0:0>4X}".format(int(leftLegBin, 2))

    h_i = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            (bytes.fromhex(leftLegHex), bytes.fromhex(hsig)))
    ).hexdigest()
    return h_i


def computeRhoi(phi, hsig, i):
    """
    Returns rho_i = blake2s(0 || i || 10 || [phi]_252 || hsig)
    See: Zcash protocol spec p. 57, Section 5.4.2 Pseudo Random Functions
    """

    # [SANITY CHECK] make sure i is in the interval [0, 1]
    # Since we only allow for 2 input notes in the joinsplit
    if i not in [0, 1]:
        return -1

    # Append PRF^{rho} tag to a_sk
    binaryPhi = hexadecimalDigestToBinaryString(phi)
    first252Phi = binaryPhi[:252]
    leftLegBin = "0" + str(i) + "10" + first252Phi
    leftLegHex = "{0:0>4X}".format(int(leftLegBin, 2))

    rho_i = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            (bytes.fromhex(leftLegHex), bytes.fromhex(hsig)))
    ).hexdigest()
    return rho_i


def int64ToHexadecimal(number):
    return '{:016x}'.format(number)


def deriveAPK(ask):
    """
    Returns a_pk = blake2s(1100 || [a_sk]_252 || 0^256)
    """
    binaryAsk = hexadecimalDigestToBinaryString(ask)
    first252Ask = binaryAsk[:252]
    leftLegBin = "1100" + first252Ask
    leftLegHex = "{0:0>4X}".format(int(leftLegBin, 2))
    zeroes = "0000000000000000000000000000000000000000000000000000000000000000"
    a_pk = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            (bytes.fromhex(leftLegHex), bytes.fromhex(zeroes)))
    ).hexdigest()
    return a_pk


def generateApkAskKeypair():
    a_sk = bytes(Random.get_random_bytes(32)).hex()
    a_pk = deriveAPK(a_sk)
    keypair = {
        "aSK": a_sk,
        "aPK": a_pk
    }
    return keypair


def createJSInput(merklePath, address, note, ask, nullifier):
    jsInput = util_pb2.JSInput(
        merkleNode=merklePath,
        address=address,
        note=note,
        spendingASK=ask,
        nullifier=nullifier
    )
    return jsInput


def generateOTSchnorrVkSkpair():
    x = int(bytes(Random.get_random_bytes(32)).hex(), 16) % constants.ZETH_PRIME
    X = ec.multiply(ec.G1, x)
    y = int(bytes(Random.get_random_bytes(32)).hex(), 16) % constants.ZETH_PRIME
    Y = ec.multiply(ec.G1, y)
    keypair = {
        "sk": [x, y],
        "vk": [X, Y]
    }
    return keypair


def encodeToHash(messages):
    """
    Encode a list of variables, or list of lists of variables into a byte
    vector
    """
    input_sha = bytearray()

    # Flatten messages
    if any(isinstance(el, list) for el in messages):
        new_list = []
        for el in messages:
            if type(el) == list:
                new_list.extend(el)
            else:
                new_list.append(el)
        messages = new_list

    for m in messages:
        # For each element
        m_hex = m

        # Convert it into a hex
        if type(m) == int:
            m_hex = "{0:0>4X}".format(m)
        elif (type(m) == str) and (m[1] == "x"):
            m_hex = m[2:]

        # [SANITY CHECK] Make sure the hex is 32 byte long
        m_hex = hex32bytes(m_hex)

        # Encode the hex into a byte array and append it to result
        input_sha += encode_single("bytes32", bytes.fromhex(m_hex))

    return input_sha


def encodeInputToHash(messages):
    """
    Encode the primary inputs as defined in ZCash chapter 4.15.1 into a byte
    array (https://github.com/zcash/zips/blob/master/protocol/protocol.pdf) The
    root, nullifierS, commitmentS, h_sig and h_iS are encoded over two field
    elements The public values are encoded over one field element
    """
    input_sha = bytearray()

    # Flatten the input list
    if any(isinstance(el, list) for el in messages):
        new_list = []
        for el in messages:
            if type(el) == list:
                new_list.extend(el)
            else:
                new_list.append(el)
        messages = new_list

    # Encode the given Merkle Tree root
    root = hex32bytes(messages[0][2:])
    root_encoded = encode_single("bytes32", bytes.fromhex(root))
    input_sha += root_encoded

    # Encode the given input nullifiers
    for i in range(1, 1 + 2*(constants.JS_INPUTS), 2):
        nf = fieldsToThex(messages[i], messages[i+1])
        nf_encoded = encode_single("bytes32", bytes.fromhex(nf))
        input_sha += nf_encoded

    # Encode the given output commitments
    for i in range(1 + 2*(constants.JS_INPUTS), 1 + 2*(constants.JS_INPUTS + constants.JS_OUTPUTS), 2):
        cm = fieldsToThex(messages[i], messages[i+1])
        cm_encoded = encode_single("bytes32", bytes.fromhex(cm))
        input_sha += cm_encoded

    # Encode the public value in
    v_in = messages[1 + 2*(constants.JS_INPUTS + constants.JS_OUTPUTS)][2:]
    v_in = hex32bytes(v_in)
    vin_encoded = encode_single("bytes32", bytes.fromhex(v_in))
    input_sha += vin_encoded

    # Encode the public value out
    v_out = messages[1 + 2*(constants.JS_INPUTS + constants.JS_OUTPUTS) + 1][2:]
    v_out = hex32bytes(v_out)
    vout_encoded = encode_single("bytes32", bytes.fromhex(v_out))
    input_sha += vout_encoded

    # Encode the h_sig
    hsig = fieldsToThex(
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
        hi = fieldsToThex(messages[i], messages[i+1])
        hi_encoded = encode_single("bytes32", bytes.fromhex(hi))
        input_sha += hi_encoded

    return input_sha


def fieldsToThex(longfield, shortfield):
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
    res = hex32bytes("{0:0>4X}".format(int(res, 2)))

    return res


def sign(keypair, hash_ciphers, hash_proof, hash_inputs):
    """
    Generate a Schnorr one-time signature of the ciphertexts, proofs and
    primary inputs We chose to sign the hash of the proof for modularity (to
    use the same code regardless of whether GROTH16 or PGHR13 proof system is
    chosen), and sign the hash of the ciphers and inputs for consistency.
    """
    # Parse the signature key pair
    vk = keypair["vk"]
    sk = keypair["sk"]

    # Format part of the public key as an hex
    y0_hex = hex32bytes("{0:0>4X}".format(int(vk[1][0])))
    y1_hex = hex32bytes("{0:0>4X}".format(int(vk[1][1])))

    # Encode and hash the verifying key and input hashes
    data_to_sign = encode_abi(
        ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
        (
            bytes.fromhex(y0_hex),
            bytes.fromhex(y1_hex),
            bytes.fromhex(hash_ciphers),
            bytes.fromhex(hash_proof),
            bytes.fromhex(hash_inputs)
        )
    )
    data_hex = sha256(data_to_sign).hexdigest()

    # Convert the hex digest into a field element
    h = int(data_hex, 16) % constants.ZETH_PRIME

    # Compute the signature sigma
    sigma = sk[1] + h * sk[0] % constants.ZETH_PRIME

    return sigma


def parseHexadecimalPointBaseGroup1Affine(point):
    return [point.xCoord, point.yCoord]


def parseHexadecimalPointBaseGroup2Affine(point):
    return [
        [point.xC1Coord, point.xC0Coord],
        [point.yC1Coord, point.yC0Coord]
    ]


def makeEmptyMessage():
    return empty_pb2.Empty()


def parseVerificationKeyPGHR13(vkObj):
    vkJSON = {}
    vkJSON["a"] = parseHexadecimalPointBaseGroup2Affine(
        vkObj.r1csPpzksnarkVerificationKey.a)
    vkJSON["b"] = parseHexadecimalPointBaseGroup1Affine(
        vkObj.r1csPpzksnarkVerificationKey.b)
    vkJSON["c"] = parseHexadecimalPointBaseGroup2Affine(
        vkObj.r1csPpzksnarkVerificationKey.c)
    vkJSON["g"] = parseHexadecimalPointBaseGroup2Affine(
        vkObj.r1csPpzksnarkVerificationKey.g)
    vkJSON["gb1"] = parseHexadecimalPointBaseGroup1Affine(
        vkObj.r1csPpzksnarkVerificationKey.gb1)
    vkJSON["gb2"] = parseHexadecimalPointBaseGroup2Affine(
        vkObj.r1csPpzksnarkVerificationKey.gb2)
    vkJSON["z"] = parseHexadecimalPointBaseGroup2Affine(
        vkObj.r1csPpzksnarkVerificationKey.z)
    vkJSON["IC"] = json.loads(vkObj.r1csPpzksnarkVerificationKey.IC)
    return vkJSON


def parseVerificationKeyGROTH16(vkObj):
    vkJSON = {}
    vkJSON["alpha_g1"] = parseHexadecimalPointBaseGroup1Affine(vkObj.r1csGgPpzksnarkVerificationKey.alpha_g1)
    vkJSON["beta_g2"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csGgPpzksnarkVerificationKey.beta_g2)
    vkJSON["delta_g2"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csGgPpzksnarkVerificationKey.delta_g2)
    vkJSON["abc_g1"] = json.loads(vkObj.r1csGgPpzksnarkVerificationKey.abc_g1)
    return vkJSON


def parseVerificationKey(vkObj, zksnark):
    if zksnark == constants.PGHR13_ZKSNARK:
        return parseVerificationKeyPGHR13(vkObj)
    elif zksnark == constants.GROTH16_ZKSNARK:
        return parseVerificationKeyGROTH16(vkObj)
    else:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)


def writeVerificationKey(vkObj, zksnark):
    """
    Writes the verification key (object) in a json file
    """
    vkJSON = parseVerificationKey(vkObj, zksnark)
    setupDir = get_trusted_setup_dir()
    filename = os.path.join(setupDir, "vk.json")
    with open(filename, 'w') as outfile:
        json.dump(vkJSON, outfile)


def makeProofInputs(root, jsInputs, jsOutputs, inPubValue, outPubValue, hsig, phi):
    return prover_pb2.ProofInputs(
        root=root,
        jsInputs=jsInputs,
        jsOutputs=jsOutputs,
        inPubValue=inPubValue,
        outPubValue=outPubValue,
        hSig=hsig,
        phi=phi
    )


def parseProofPGHR13(proofObj):
    proofJSON = {}
    proofJSON["a"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.a)
    proofJSON["a_p"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.aP)
    proofJSON["b"] = parseHexadecimalPointBaseGroup2Affine(proofObj.r1csPpzksnarkExtendedProof.b)
    proofJSON["b_p"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.bP)
    proofJSON["c"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.c)
    proofJSON["c_p"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.cP)
    proofJSON["h"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.h)
    proofJSON["k"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csPpzksnarkExtendedProof.k)
    proofJSON["inputs"] = json.loads(proofObj.r1csPpzksnarkExtendedProof.inputs)
    return proofJSON


def parseProofGROTH16(proofObj):
    proofJSON = {}
    proofJSON["a"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csGgPpzksnarkExtendedProof.a)
    proofJSON["b"] = parseHexadecimalPointBaseGroup2Affine(proofObj.r1csGgPpzksnarkExtendedProof.b)
    proofJSON["c"] = parseHexadecimalPointBaseGroup1Affine(proofObj.r1csGgPpzksnarkExtendedProof.c)
    proofJSON["inputs"] = json.loads(proofObj.r1csGgPpzksnarkExtendedProof.inputs)
    return proofJSON


def parseProof(proofObj, zksnark):
    if zksnark == constants.PGHR13_ZKSNARK:
        return parseProofPGHR13(proofObj)
    elif zksnark == constants.GROTH16_ZKSNARK:
        return parseProofGROTH16(proofObj)
    else:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)


def getProofJoinsplit2By2(
        grpcEndpoint,
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
        zksnark):
    input_nullifier0 = computeNullifier(input_note0, sender_ask)
    input_nullifier1 = computeNullifier(input_note1, sender_ask)
    js_inputs = [
        createJSInput(
            mk_path0, input_address0, input_note0, sender_ask, input_nullifier0),
        createJSInput(
            mk_path1, input_address1, input_note1, sender_ask, input_nullifier1)
    ]

    randomSeed = signatureRandomness()
    # Generate (joinSplitPubKey, joinSplitPrivKey) key pair
    joinsplit_keypair = generateOTSchnorrVkSkpair()
    h_sig = computeHSig(randomSeed, input_nullifier0, input_nullifier1, joinsplit_keypair["vk"])
    phi = transactionRandomness()

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

    proof_input = makeProofInputs(mk_root, js_inputs, js_outputs, public_in_value, public_out_value, h_sig, phi)
    proof_obj = getProof(grpcEndpoint, proof_input)
    proof_json = parseProof(proof_obj, zksnark)

    # We return the zeth notes to be able to spend them later
    # and the proof used to create them
    return (output_note0, output_note1, proof_json, joinsplit_keypair)
