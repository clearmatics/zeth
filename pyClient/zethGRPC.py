from Crypto import Random
import os
import json
import hashlib

# Access the encoding functions
from eth_abi import encode_single, encode_abi

# Access the gRPC service and the proto messages
import grpc
import util_pb2
import util_pb2_grpc
import bctv14_messages_pb2
import bctv14_messages_pb2_grpc
import groth16_messages_pb2
import groth16_messages_pb2_grpc
import prover_pb2
import prover_pb2_grpc

# Fetch the verification key from the proving service
def getVerificationKey(grpcEndpoint):
    with grpc.insecure_channel(grpcEndpoint) as channel:
        stub = prover_pb2_grpc.ProverStub(channel)
        print("-------------- Get the verification key --------------")
        verificationkey = stub.GetVerificationKey(make_empty_message())
        return verificationkey

# Request a proof generation to the proving service
def getProof(grpcEndpoint, proofInputs):
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

def noteRandomness():
    rand_rho = bytes(Random.get_random_bytes(32)).hex()
    rand_trapR = bytes(Random.get_random_bytes(48)).hex()
    randomness = {
        "rho": rand_rho,
        "trapR": rand_trapR
    }
    return randomness

# We follow the formatting of the proto file
def createZethNote(randomness, recipientApk, value):
    note = util_pb2.ZethNote(
        aPK=recipientApk,
        value=value,
        rho=randomness["rho"],
        trapR=randomness["trapR"]
    )
    return note

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

# Used by the recipient of a payment to recompute the commitment and check the membership in the tree
# to confirm the validity of a payment
def computeCommitment(zethNoteGRPCObj):
    # inner_k = sha256(a_pk || rho)
    inner_k = hashlib.sha256(
        encode_abi(['bytes32', 'bytes32'], (bytes.fromhex(zethNoteGRPCObj.aPK), bytes.fromhex(zethNoteGRPCObj.rho)))
    ).hexdigest()

    # outer_k = sha256(r || [inner_k]_128)
    first128InnerComm = inner_k[0:128]
    outer_k = hashlib.sha256(
        encode_abi(['bytes', 'bytes'], (bytes.fromhex(zethNoteGRPCObj.trapR), bytes.fromhex(first128InnerComm)))
    ).hexdigest()

    # cm = sha256(outer_k || 0^192 || value_v)
    frontPad = "000000000000000000000000000000000000000000000000"
    cm = hashlib.sha256(
        encode_abi(["bytes32", "bytes32"], (bytes.fromhex(outer_k), bytes.fromhex(frontPad + zethNoteGRPCObj.value)))
    ).hexdigest()
    return cm

def hexadecimalDigestToBinaryString(digest):
    binary = lambda x: "".join(reversed( [i+j for i,j in zip( *[ ["{0:04b}".format(int(c,16)) for c in reversed("0"+x)][n::2] for n in [1,0]])]))
    return binary(digest)

def computeNullifier(zethNote, spendingAuthAsk):
    # nf = sha256(a_sk || 01 || [rho]_254)
    binaryRho = hexadecimalDigestToBinaryString(zethNote.rho)
    first254Rho = binaryRho[0:254]
    rightLegBin = "01" + first254Rho
    rightLegHex = "{0:0>4X}".format(int(rightLegBin, 2))
    print("Compute nullifier")
    nullifier = hashlib.sha256(
        encode_abi(["bytes32", "bytes32"], [bytes.fromhex(spendingAuthAsk), bytes.fromhex(rightLegHex)])
    ).hexdigest()
    return nullifier

def int64ToHexadecimal(number):
    return '{:016x}'.format(number)

def deriveAPK(ask):
    # a_pk = sha256(a_sk || 0^256)
    zeroes = "0000000000000000000000000000000000000000000000000000000000000000"
    a_pk = hashlib.sha256(
        encode_abi(["bytes32", "bytes32"], [bytes.fromhex(ask), bytes.fromhex(zeroes)])
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

def parseHexadecimalPointBaseGroup1Affine(point):
  return [point.xCoord, point.yCoord]

def parseHexadecimalPointBaseGroup2Affine(point):
  return [
    [point.xC1Coord, point.xC0Coord],
    [point.yC1Coord, point.yC0Coord]
  ]

def make_empty_message():
    return prover_pb2.EmptyMessage()

def parseVerificationKey(vkObj):
    vkJSON = {}
    vkJSON["a"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csPpzksnarkVerificationKey.a)
    vkJSON["b"] = parseHexadecimalPointBaseGroup1Affine(vkObj.r1csPpzksnarkVerificationKey.b)
    vkJSON["c"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csPpzksnarkVerificationKey.c)
    vkJSON["g"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csPpzksnarkVerificationKey.g)
    vkJSON["gb1"] = parseHexadecimalPointBaseGroup1Affine(vkObj.r1csPpzksnarkVerificationKey.gb1)
    vkJSON["gb2"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csPpzksnarkVerificationKey.gb2)
    vkJSON["z"] = parseHexadecimalPointBaseGroup2Affine(vkObj.r1csPpzksnarkVerificationKey.z)
    vkJSON["IC"] = json.loads(vkObj.r1csPpzksnarkVerificationKey.IC)
    return vkJSON

# Writes the verification key (object) in a json file
def writeVerificationKey(vkObj):
    vkJSON = parseVerificationKey(vkObj)
    setupDir = os.environ['ZETH_TRUSTED_SETUP_DIR']
    filename = os.path.join(setupDir, "vk.json")
    with open(filename, 'w') as outfile:
        json.dump(vkJSON, outfile)

def makeProofInputs(root, jsInputs, jsOutputs, inPubValue, outPubValue):
    return prover_pb2.ProofInputs(
        root=root,
        jsInputs=jsInputs,
        jsOutputs=jsOutputs,
        inPubValue=inPubValue,
        outPubValue=outPubValue
    )

def parseProof(proofObj):
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

def get_proof_joinsplit_2by2(
        grpcEndpoint,
        mk_root,
        input_note1,
        input_address1,
        mk_path1,
        input_note2,
        input_address2,
        mk_path2,
        sender_ask,
        recipient1_apk,
        recipient2_apk,
        output_note_value1,
        output_note_value2,
        public_in_value,
        public_out_value
    ):
    input_nullifier1 = computeNullifier(input_note1, sender_ask)
    input_nullifier2 = computeNullifier(input_note2, sender_ask)
    js_inputs = [
        createJSInput(mk_path1, input_address1, input_note1, sender_ask, input_nullifier1),
        createJSInput(mk_path2, input_address2, input_note2, sender_ask, input_nullifier2)
    ]

    output_note1 = createZethNote(noteRandomness(), recipient1_apk, output_note_value1)
    output_note2 = createZethNote(noteRandomness(), recipient2_apk, output_note_value2)
    js_outputs = [
        output_note1,
        output_note2
    ]

    proof_input = makeProofInputs(mk_root, js_inputs, js_outputs, public_in_value, public_out_value)
    proof_obj = getProof(grpcEndpoint, proof_input)
    proof_json = parseProof(proof_obj)

    # We return the zeth notes to be able to spend them later
    # and the proof used to create them
    return (output_note1, output_note2, proof_json)
