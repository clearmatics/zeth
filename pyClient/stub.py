import random
import logging
import json
import os

from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider

# Get the utils written to interact with the prover
import zethUtils as zeth

# grpc modules
import grpc
import prover_pb2
import prover_pb2_grpc

def make_empty_message():
    return prover_pb2.EmptyMessage()

# Fetch the verification kwy from the proving service
def getVerificationKey():
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = prover_pb2_grpc.ProverStub(channel)
        print("-------------- GetVerificationKey --------------")
        verificationkey = stub.GetVerificationKey(make_empty_message());
        return verificationkey # verificationKey is an object here

# Writes the verification key (object) in a json file
def writeVerificationKey(vkObj):
    vkJSON = {}
    vkJSON["a"] = zeth.parseHexadecimalPointBaseGroup2Affine(vkObj.a)
    vkJSON["b"] = zeth.parseHexadecimalPointBaseGroup1Affine(vkObj.b)
    vkJSON["c"] = zeth.parseHexadecimalPointBaseGroup2Affine(vkObj.c)
    vkJSON["g"] = zeth.parseHexadecimalPointBaseGroup2Affine(vkObj.g)
    vkJSON["gb1"] = zeth.parseHexadecimalPointBaseGroup1Affine(vkObj.gb1)
    vkJSON["gb2"] = zeth.parseHexadecimalPointBaseGroup2Affine(vkObj.gb2)
    vkJSON["z"] = zeth.parseHexadecimalPointBaseGroup2Affine(vkObj.z)
    vkJSON["IC"] = json.loads(vkObj.IC)

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

def getProof(proofInputs):
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = prover_pb2_grpc.ProverStub(channel)
        print("-------------- GetProof --------------")
        proof = stub.Prove(proofInputs)
        return proof # proof is an object here

def testcase1():
    print("BOB deposits 7 ETH for himself")
    keystore = zeth.initTestKeystore()
    zeroWei = "0000000000000000000"
    zeroWeiHex = "0000000000000000"

    bobAPK = keystore["Bob"]["AddrPk"]["aPK"] # we generate a coin for Bob (recipient)
    bobASK = keystore["Bob"]["AddrSk"]["aSK"]
    noteBobIn = zeth.createZethNote(zeth.noteRandomness(), bobAPK, zeroWeiHex)
    nullifierIn = zeth.computeNullifier(noteBobIn, bobASK)

    root = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    merklePath = [
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    ]
    jsInputs = [
        zeth.createJSInput(merklePath, 7, noteBobIn, bobASK, nullifierIn)
    ]

    valueOut = zeth.int64ToHexadecimal(Web3.toWei('4', 'ether')) # Note of value 4 as output of the JS
    noteBobOut = zeth.createZethNote(zeth.noteRandomness(), bobAPK, valueOut)
    nullifierOut = zeth.computeNullifier(noteBobOut, bobASK)
    jsOutputs = [
        noteBobOut
    ]

    inPubValue = zeth.int64ToHexadecimal(Web3.toWei('4', 'ether'))
    outPubValue = zeroWeiHex # No pub output

    proofInput = makeProofInputs(root, jsInputs, jsOutputs, inPubValue, outPubValue)
    print("before get proof")
    resProof = getProof(proofInput)
    print("after get proof")

    print(resProof)
    return


if __name__ == '__main__':
    logging.basicConfig();
    vk = getVerificationKey()
    print("Received VK")
    writeVerificationKey(vk)
    print("Wrote VK")
    testcase1()
    print("Test case 1 done")
