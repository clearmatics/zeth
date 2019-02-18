from Crypto import Random
#from eth_abi.packed import encode_single_packed, encode_abi_packed
#import eth_abi
from eth_abi import encode_single, encode_abi
import hashlib

import prover_pb2
import prover_pb2_grpc

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
    #binary = lambda x: "".join(reversed( [i+j for i,j in zip( *[ ["{0:04b}".format(int(c,16)) for c in reversed("0"+x)][n::2] for n in [1,0]])]))
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

# Keystore for the tests
def initTestKeystore():
    # Alice credentials in the zeth abstraction
    AliceOwnershipKeys = generateApkAskKeypair()
    AliceEncKey = """-----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDP34BAdxAX0p9yxhcoqkQtCKWc
    o/t/MEqLfjCP/dwkrN9MmML4CGYXqF0X9UKxv+2qxhtxkLLFtPnyT6PRTQDnPuHw
    +D8kQ4DOyn5fBVpIwvPVl/COIZYiSQgv2YaE8UI/9YtXLE9njJItsCJQbtcKY6TZ
    8JmIxk2E9fNah9V+SQIDAQAB
    -----END PUBLIC KEY-----"""
    AliceDecKey = """-----BEGIN RSA PRIVATE KEY-----
    MIICWgIBAAKBgQDP34BAdxAX0p9yxhcoqkQtCKWco/t/MEqLfjCP/dwkrN9MmML4
    CGYXqF0X9UKxv+2qxhtxkLLFtPnyT6PRTQDnPuHw+D8kQ4DOyn5fBVpIwvPVl/CO
    IZYiSQgv2YaE8UI/9YtXLE9njJItsCJQbtcKY6TZ8JmIxk2E9fNah9V+SQIDAQAB
    An92hzpoMl86xHOmk3fLv0pnnCon5wOkF7NNVspoM+2hGGM7F/xM8Zl98hfNpr1Z
    q2TEEM6G+fPZZFEEfToPJSdzAf1GUPBNeIr/iJCERM1UzlRb1C09jil1Spne3NSa
    xYx3JVZs2WEhz/RAELuRzMBqntDNYmbUhhPEZ3S4WIBNAkEA3KvB1JvmJp5+S72S
    7JGsiH3iP0q/MsyLdZFyOtBiUlcmJ67iTDPR/sTF/o4jZrFQf8heGDRzvgLbqxbz
    NsIy1QJBAPEnOGUs8qo8JsIQv7khx3HDXO1pVA4WfL9i+G9AQKUtbN0pi8kErBCy
    KShUEsQQfx69r2BkUO/mxXuTKUKPT6UCQEQ8FBaTEmq0rabr+seOEASwsEoT6eVi
    XGlBTUokb5K4ggLZT/5yM6gM3pBlEUtK3vJ0WawwY+3IYnaYBSLUj/UCQFeK5Fce
    RQ11fqBukhrz30I2KJLq7J+cnDaiCAvi6FTOM7nprhwQPSJmerhwJMvWLT+MnpDA
    ef1M6h3dI1pNSh0CQQCjEQ/5Udy3YjQQfE1f+sW2CnosVGP7VZFhVyAT+KBxm8Sh
    YnR+rry8uG5XUjjkxOVoRDEZMx2uErlklDhYy4r0
    -----END RSA PRIVATE KEY-----"""

    # Bob credentials in the zeth abstraction
    BobOwnershipKeys = generateApkAskKeypair()
    BobEncKey = """-----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3Ba45mM+JhO9tNpHwldnnvAtA
    /j2XqiV4HNhkql39vt76oy6RV7Yl3KIW+dsT5EwZos8NmgvWo28pC4u+4nXbuNLH
    WVVt1jHQVhG9EQRlbkoCypDD4wOmrdlJplCjaRgCSeN8U7G+MTr2AtRT+0VozV04
    mIoKPDymx+pgH8KJVQIDAQAB
    -----END PUBLIC KEY-----"""
    BobDecKey = """-----BEGIN RSA PRIVATE KEY-----
    MIICXAIBAAKBgQC3Ba45mM+JhO9tNpHwldnnvAtA/j2XqiV4HNhkql39vt76oy6R
    V7Yl3KIW+dsT5EwZos8NmgvWo28pC4u+4nXbuNLHWVVt1jHQVhG9EQRlbkoCypDD
    4wOmrdlJplCjaRgCSeN8U7G+MTr2AtRT+0VozV04mIoKPDymx+pgH8KJVQIDAQAB
    AoGBAJ7wNvHby3cgU5AjUK9+YuKEgb1qTHC2GJ3rZtxcuw0NwbQlG96qLgtJRBXx
    2xe2LYQhx++G9HrsKS+a0Dvvi+rQ7YK7cxFJuKNmwonoKI9LpIFDV7xvNJ1TPU1G
    QVskoU1OfwUabyDmYI5j7Lgf2xqu7Z2xNz1iQoMzFvI+ffItAkEA2GY+N3E3ZJWP
    +E6OuZHD08E0h9mPGoug5YQjhYEV0zyI9abGCzDZp90YKoLerTJefaD5NyErRVFn
    7jnFYGjxewJBANiDzSTMUeojGWboRhfHl/2FNSjg7ClgI8tjdH72Rn46EbLJHgno
    L3j5O1XwwgtbjTb/vRpc0V+gQp32qSlw728CQAhPnPIaKgt15wqdUcP0wjWexPq2
    s1VMqYhHE+ors//h4ky09AQ4AxP8XNI9Jno2ZgSjKw8f+f52iuxOUbNLNIMCQFfs
    vkQxTRqeAlTOApjpjwl/LOVa4cyzpBWWX9qnPF1KS6GlFrPDPHQOElCGIubl2OT6
    2dp40vXYaPUpE+0mVbUCQCxw7IvglwRKc142K7HfsSOdn0bQplS3ezEthriIzacP
    CCePPHuHI3A7+3ROFMKXmmjDauEMcpLhQen5f4/Corg=
    -----END RSA PRIVATE KEY-----"""

    # Charlie credentials in the zeth abstraction
    CharlieOwnershipKeys = generateApkAskKeypair()
    CharlieEncKey = """-----BEGIN RSA PRIVATE KEY-----
    MIICWwIBAAKBgQDz6F8PhRiHVCnfq5jxOx+N8Usov35NJSWQ3R/iRmNK+BeNedXb
    qvunEbLPEdus5h9BE2RwR0wumDe7WJWIjjRLEU7C5dJGDEviWlJBC+yw0wbnWA5F
    V6Mrq0UJSLVe5Q5uiLuHuzI9Ag9UOqJZTXQ5yfG89QRE8HumA1tzfxCrQwIDAQAB
    AoGATQ6v4bZZ7n9Pj2OmOShFqtF9vkzpeTPwL1k89n7oZcoFnuPMBc96G+lChZsN
    vQ0i+KtIwxQzZFEg4mZ1L6RFrofOyveFxsdI3LdpAbIKZujfatnsIjvjfYuZtV71
    63oP9HAbQnatrx3vhzZgw+FoIp/0M14J3wmHC/GpdLGxABkCQQD32fzy0lSzqVTp
    elxw7U+Rkze9WPcUEQYyaFDiB4COTudFwVTxoBZd2vxfbxpfr03no59shslZxzcl
    GWPs2gbnAkEA++0wy+H7DSTSQaDFsciVId6qAvNfM9wEUpq1WepvZTvOhyULp9PI
    TrxCtvYKPjKqU/7rPsJ8eVbBoAlhDJXZRQJAeu3imKkbm7R7ygWHffcmBOUIu2A5
    w/khorS8kS75Yxvdd2qJcAJftZNcoxTe9uBi+mXcN56ulVnKjxsFxb7ptwJAWixi
    RPgURnYhlEAZwzMKvl7W98tpDkT4fyDFPPP+/3tSx2jpLR9PGW+laZvTusOj2ADs
    7z/qEfyNvdzdkgWpCQJAZyTN+aWuoqhR9h3fsCLy4NisJ3z5reViXZVMKW4J8jat
    aKtIj2rMlUbT+hLkAQmUb4YZwxtPibPTIUFTwrHmiw==
    -----END RSA PRIVATE KEY-----"""
    CharlieDecKey = """-----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDz6F8PhRiHVCnfq5jxOx+N8Uso
    v35NJSWQ3R/iRmNK+BeNedXbqvunEbLPEdus5h9BE2RwR0wumDe7WJWIjjRLEU7C
    5dJGDEviWlJBC+yw0wbnWA5FV6Mrq0UJSLVe5Q5uiLuHuzI9Ag9UOqJZTXQ5yfG8
    9QRE8HumA1tzfxCrQwIDAQAB
    -----END PUBLIC KEY-----"""

    keystore = {
        "Alice": {
            "AddrPk": {
                "ek": AliceEncKey,
                "aPK": AliceOwnershipKeys["aPK"]
            },
            "AddrSk": {
                "dk": AliceDecKey,
                "aSK": AliceOwnershipKeys["aSK"]
            }
        },
        "Bob": {
            "AddrPk": {
                "ek": BobEncKey,
                "aPK": BobOwnershipKeys["aPK"]
            },
            "AddrSk": {
                "dk": BobDecKey,
                "aSK": BobOwnershipKeys["aSK"]
            }
        },
        "Charlie": {
            "AddrPk": {
                "ek": CharlieEncKey,
                "aPK": CharlieOwnershipKeys["aPK"]
            },
            "AddrSk": {
                "dk": CharlieDecKey,
                "aSK": CharlieOwnershipKeys["aSK"]
            }
        }
    }
    return keystore
