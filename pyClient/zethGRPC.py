from Crypto import Random
import os
import json
import hashlib

# Access the encoding functions
from eth_abi import encode_single, encode_abi

# Access the gRPC service and the proto messages
import grpc
import prover_pb2
import prover_pb2_grpc

# Fetch the verification key from the proving service
def getVerificationKey(grpcEndpoint):
    with grpc.insecure_channel(grpcEndpoint) as channel:
        stub = prover_pb2_grpc.ProverStub(channel)
        print("-------------- Get the verification key --------------")
        verificationkey = stub.GetVerificationKey(make_empty_message());
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
    note = prover_pb2.ZethNote(
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

def hexFmt(string):
    return "0x" + string

"""
def computeCommitment(zethNote):
    # inner_k = sha256(a_pk || rho)
    inner_k = hashlib.sha256(
        encode_abi(['bytes32', 'bytes32'], (hexFmt(zethNote["aPK"]), hexFmt(zethNote["rho"])))
    ).hexdigest()

    # outer_k = sha256(r || [inner_k]_128)
    first128InnerComm = inner_k[0:128];
    outer_k = hashlib.sha256(
        encode_abi(['string', 'string'], (hexFmt(zethNote["trapR"]), hexFmt(first128InnerComm)))
    ).hexdigest()

    # cm = sha256(outer_k || 0^192 || value_v)
    frontPad = "000000000000000000000000000000000000000000000000";
    cm = hashlib.sha256(
        encode_abi(["bytes32", "bytes32"], (hexFmt(outer_k), hexFmt(frontPad + zethNote["value"])))
    ).hexdigest()
    return cm
"""

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
    zeroes = "0000000000000000000000000000000000000000000000000000000000000000";
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
    jsInput = prover_pb2.JSInput(
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
    vkJSON["a"] = parseHexadecimalPointBaseGroup2Affine(vkObj.a)
    vkJSON["b"] = parseHexadecimalPointBaseGroup1Affine(vkObj.b)
    vkJSON["c"] = parseHexadecimalPointBaseGroup2Affine(vkObj.c)
    vkJSON["g"] = parseHexadecimalPointBaseGroup2Affine(vkObj.g)
    vkJSON["gb1"] = parseHexadecimalPointBaseGroup1Affine(vkObj.gb1)
    vkJSON["gb2"] = parseHexadecimalPointBaseGroup2Affine(vkObj.gb2)
    vkJSON["z"] = parseHexadecimalPointBaseGroup2Affine(vkObj.z)
    vkJSON["IC"] = json.loads(vkObj.IC)
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
    proofJSON["a"] = parseHexadecimalPointBaseGroup1Affine(proofObj.a)
    proofJSON["a_p"] = parseHexadecimalPointBaseGroup1Affine(proofObj.aP)
    proofJSON["b"] = parseHexadecimalPointBaseGroup2Affine(proofObj.b)
    proofJSON["b_p"] = parseHexadecimalPointBaseGroup1Affine(proofObj.bP)
    proofJSON["c"] = parseHexadecimalPointBaseGroup1Affine(proofObj.c)
    proofJSON["c_p"] = parseHexadecimalPointBaseGroup1Affine(proofObj.cP)
    proofJSON["h"] = parseHexadecimalPointBaseGroup1Affine(proofObj.h)
    proofJSON["k"] = parseHexadecimalPointBaseGroup1Affine(proofObj.k)
    proofJSON["inputs"] = json.loads(proofObj.inputs)
    return proofJSON
