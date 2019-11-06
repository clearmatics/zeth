from Crypto import Random
import os
import json
import sys

# Access the encoding and hash functions
from eth_abi import encode_single, encode_abi
from hashlib import blake2s, sha256

# Access the gRPC service and the proto messages
import grpc  # type: ignore
from google.protobuf import empty_pb2
import api.util_pb2 as util_pb2  # type: ignore
import api.prover_pb2 as prover_pb2  # type: ignore
import api.prover_pb2_grpc as prover_pb2_grpc  # type: ignore

import zeth.constants as constants
import zeth.errors as errors
from zeth.utils import get_trusted_setup_dir, hex_extend_32bytes, \
    hex_digest_to_binary_string

# Import elliptic curve operations
from py_ecc import bn128 as ec


def get_verification_key(grpc_endpoint):
    """
    Fetch the verification key from the proving service
    """
    with grpc.insecure_channel(grpc_endpoint) as channel:
        stub = prover_pb2_grpc.ProverStub(channel)
        print("-------------- Get the verification key --------------")
        verification_key = stub.GetVerificationKey(make_empty_message())
        return verification_key


def get_proof(grpc_endpoint, proof_inputs):
    """
    Request a proof generation to the proving service
    """
    with grpc.insecure_channel(grpc_endpoint) as channel:
        stub = prover_pb2_grpc.ProverStub(channel)
        print("-------------- Get the proof --------------")
        proof = stub.Prove(proof_inputs)
        return proof


def compute_h_sig(random_seed, nf0, nf1, joinsplit_pub_key):
    """
    Compute h_sig = blake2s(random_seed, nf0, nf1, joinsplit_pub_key)
    Flatten the verification key
    """
    joinsplit_pub_key_hex = [item for sublist in joinsplit_pub_key for item in sublist]

    vk_hex = ""
    for item in joinsplit_pub_key_hex:
        # For each element of the list, convert it to an hex and append it
        vk_hex += hex_extend_32bytes("{0:0>4X}".format(int(item)))

    h_sig = blake2s(
        encode_abi(
            ['bytes32', 'bytes32', 'bytes32', 'bytes'],
            (
                bytes.fromhex(random_seed),
                bytes.fromhex(nf0),
                bytes.fromhex(nf1),
                bytes.fromhex(vk_hex)
            )
        )
    ).hexdigest()

    return h_sig


def gen_signature_randomness():
    """
    Compute the signature randomness "random_seed", used for computing h_sig
    """
    random_seed = bytes(Random.get_random_bytes(32)).hex()
    return random_seed


def gen_transaction_randomness():
    """
    Compute the transaction randomness "phi", used for computing the new rhoS
    """
    rand_phi = bytes(Random.get_random_bytes(32)).hex()
    return rand_phi


def gen_note_randomness():
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


def create_zeth_note(randomness, recipient_apk, value):
    """
    We follow the formatting of the proto file.  Create a ZethNote description
    Starting the Non-Malleability update, this function is used only for dummy
    input notes as rhoS are now structured ( rho = PRF_{phi}(i, phi, h_sig) ).
    """
    note = util_pb2.ZethNote(
        aPK=recipient_apk,
        value=value,
        rho=randomness["rho"],
        trapR=randomness["trapR"]
    )
    return note


def create_zeth_notes(phi, hsig, recipient_apk0, value0, recipient_apk1, value1):
    """
    Create two ordered ZethNotes.  This function is used to generate new output
    notes.
    """
    rho0 = compute_rho_i(phi, hsig, 0)
    randomness0 = gen_note_randomness()
    note0 = util_pb2.ZethNote(
        aPK=recipient_apk0,
        value=value0,
        rho=rho0,
        trapR=randomness0["trapR"]
    )

    rho1 = compute_rho_i(phi, hsig, 1)
    randomness1 = gen_note_randomness()
    note1 = util_pb2.ZethNote(
        aPK=recipient_apk1,
        value=value1,
        rho=rho1,
        trapR=randomness1["trapR"]
    )

    return note0, note1


def parse_zeth_note(zeth_note_grpc_obj):
    note_json = {
        "aPK": zeth_note_grpc_obj.aPK,
        "value": zeth_note_grpc_obj.value,
        "rho": zeth_note_grpc_obj.rho,
        "trapR": zeth_note_grpc_obj.trapR,
    }
    return note_json


def zeth_note_obj_from_parsed(parsed_zeth_note):
    note = util_pb2.ZethNote(
        aPK=parsed_zeth_note["aPK"],
        value=parsed_zeth_note["value"],
        rho=parsed_zeth_note["rho"],
        trapR=parsed_zeth_note["trapR"]
    )
    return note


def hex_fmt(string):
    return "0x" + string


def compute_commitment(zeth_note_grpc_obj):
    """
    Used by the recipient of a payment to recompute the commitment and check
    the membership in the tree to confirm the validity of a payment
    """
    # inner_k = blake2s(a_pk || rho)
    inner_k = blake2s(
        encode_abi(
            ['bytes32', 'bytes32'],
            (bytes.fromhex(zeth_note_grpc_obj.aPK),
             bytes.fromhex(zeth_note_grpc_obj.rho)))
    ).hexdigest()

    # outer_k = blake2s(r || [inner_k]_128)
    first_128bits_inner_comm = inner_k[0:128]
    outer_k = blake2s(
        encode_abi(
            ['bytes', 'bytes'],
            (bytes.fromhex(zeth_note_grpc_obj.trapR),
             bytes.fromhex(first_128bits_inner_comm)))).hexdigest()

    # cm = blake2s(outer_k || 0^192 || value_v)
    front_pad = "000000000000000000000000000000000000000000000000"
    cm = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            (bytes.fromhex(outer_k),
             bytes.fromhex(front_pad + zeth_note_grpc_obj.value)))
    ).hexdigest()
    return cm


def compute_nullifier(zeth_note, spending_authority_ask):
    """
    Returns nf = blake2s(1110 || [a_sk]_252 || rho)
    """
    binary_ask = hex_digest_to_binary_string(spending_authority_ask)
    first_252bits_ask = binary_ask[:252]
    left_leg_bin = "1110" + first_252bits_ask
    left_leg_hex = "{0:0>4X}".format(int(left_leg_bin, 2))
    nullifier = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            (bytes.fromhex(left_leg_hex), bytes.fromhex(zeth_note.rho)))
    ).hexdigest()
    return nullifier


def compute_h_i(ask, hsig, i):
    """
    Returns h_i = blake2s(0 || i || 00 || [a_sk]_252 || hsig)
    See: Zcash protocol spec p. 57, Section 5.4.2 Pseudo Random Functions
    """

    # [SANITY CHECK] make sure i is in the interval [0, 1]
    # Since we only allow for 2 input notes in the joinsplit
    if i not in [0, 1]:
        return -1

    # Append PRF^{pk} tag to a_sk
    binary_ask = hex_digest_to_binary_string(ask)
    first_252bits_ask = binary_ask[:252]
    left_leg_bin = "0" + str(i) + "00" + first_252bits_ask
    left_leg_hex = "{0:0>4X}".format(int(left_leg_bin, 2))

    h_i = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            (bytes.fromhex(left_leg_hex), bytes.fromhex(hsig)))
    ).hexdigest()
    return h_i


def compute_rho_i(phi, hsig, i):
    """
    Returns rho_i = blake2s(0 || i || 10 || [phi]_252 || hsig)
    See: Zcash protocol spec p. 57, Section 5.4.2 Pseudo Random Functions
    """

    # [SANITY CHECK] make sure i is in the interval [0, 1]
    # Since we only allow for 2 input notes in the joinsplit
    if i not in [0, 1]:
        return -1

    # Append PRF^{rho} tag to a_sk
    binary_phi = hex_digest_to_binary_string(phi)
    first_252bits_phi = binary_phi[:252]
    left_leg_bin = "0" + str(i) + "10" + first_252bits_phi
    left_leg_hex = "{0:0>4X}".format(int(left_leg_bin, 2))

    rho_i = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            (bytes.fromhex(left_leg_hex), bytes.fromhex(hsig)))
    ).hexdigest()
    return rho_i


def derive_apk(ask):
    """
    Returns a_pk = blake2s(1100 || [a_sk]_252 || 0^256)
    """
    binary_ask = hex_digest_to_binary_string(ask)
    first_252bits_ask = binary_ask[:252]
    left_leg_bin = "1100" + first_252bits_ask
    left_leg_hex = "{0:0>4X}".format(int(left_leg_bin, 2))
    zeroes = "0000000000000000000000000000000000000000000000000000000000000000"
    apk = blake2s(
        encode_abi(
            ["bytes32", "bytes32"],
            (bytes.fromhex(left_leg_hex), bytes.fromhex(zeroes)))
    ).hexdigest()
    return apk


def gen_apk_ask_keypair():
    ask = bytes(Random.get_random_bytes(32)).hex()
    apk = derive_apk(ask)
    keypair = {
        "ask": ask,
        "apk": apk
    }
    return keypair


def create_joinsplit_input(merkle_path, address, note, ask, nullifier):
    jsInput = util_pb2.JSInput(
        merkleNode=merkle_path,
        address=address,
        note=note,
        spendingASK=ask,
        nullifier=nullifier
    )
    return jsInput


def gen_one_time_schnorr_vk_sk_pair():
    x = int(bytes(Random.get_random_bytes(32)).hex(), 16) % constants.ZETH_PRIME
    X = ec.multiply(ec.G1, x)
    y = int(bytes(Random.get_random_bytes(32)).hex(), 16) % constants.ZETH_PRIME
    Y = ec.multiply(ec.G1, y)
    keypair = {
        "sk": [x, y],
        "vk": [X, Y]
    }
    return keypair


def encode_pub_input_to_hash(messages):
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
    root = hex_extend_32bytes(messages[0][2:])
    root_encoded = encode_single("bytes32", bytes.fromhex(root))
    input_sha += root_encoded

    # Encode the given input nullifiers
    for i in range(1, 1 + 2*(constants.JS_INPUTS), 2):
        nf = field_elements_to_hex(messages[i], messages[i+1])
        nf_encoded = encode_single("bytes32", bytes.fromhex(nf))
        input_sha += nf_encoded

    # Encode the given output commitments
    for i in range(1 + 2*(constants.JS_INPUTS), 1 + 2*(constants.JS_INPUTS + constants.JS_OUTPUTS), 2):
        cm = field_elements_to_hex(messages[i], messages[i+1])
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
    hsig = field_elements_to_hex(
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
        hi = field_elements_to_hex(messages[i], messages[i+1])
        hi_encoded = encode_single("bytes32", bytes.fromhex(hi))
        input_sha += hi_encoded

    return input_sha


def field_elements_to_hex(longfield, shortfield):
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
    y0_hex = hex_extend_32bytes("{0:0>4X}".format(int(vk[1][0])))
    y1_hex = hex_extend_32bytes("{0:0>4X}".format(int(vk[1][1])))

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


def parse_hexadecimalPointBaseGroup1Affine(point):
    return [point.xCoord, point.yCoord]


def parse_hexadecimalPointBaseGroup2Affine(point):
    return [
        [point.xC1Coord, point.xC0Coord],
        [point.yC1Coord, point.yC0Coord]
    ]


def make_empty_message():
    return empty_pb2.Empty()


def parse_verification_key_PGHR13(vk_obj):
    vk_json = {}
    vk_json["a"] = parse_hexadecimalPointBaseGroup2Affine(
        vk_obj.r1csPpzksnarkVerificationKey.a)
    vk_json["b"] = parse_hexadecimalPointBaseGroup1Affine(
        vk_obj.r1csPpzksnarkVerificationKey.b)
    vk_json["c"] = parse_hexadecimalPointBaseGroup2Affine(
        vk_obj.r1csPpzksnarkVerificationKey.c)
    vk_json["g"] = parse_hexadecimalPointBaseGroup2Affine(
        vk_obj.r1csPpzksnarkVerificationKey.g)
    vk_json["gb1"] = parse_hexadecimalPointBaseGroup1Affine(
        vk_obj.r1csPpzksnarkVerificationKey.gb1)
    vk_json["gb2"] = parse_hexadecimalPointBaseGroup2Affine(
        vk_obj.r1csPpzksnarkVerificationKey.gb2)
    vk_json["z"] = parse_hexadecimalPointBaseGroup2Affine(
        vk_obj.r1csPpzksnarkVerificationKey.z)
    vk_json["IC"] = json.loads(vk_obj.r1csPpzksnarkVerificationKey.IC)
    return vk_json


def parse_verification_key_GROTH16(vk_obj):
    vk_json = {}
    vk_json["alpha_g1"] = parse_hexadecimalPointBaseGroup1Affine(vk_obj.r1csGgPpzksnarkVerificationKey.alpha_g1)
    vk_json["beta_g2"] = parse_hexadecimalPointBaseGroup2Affine(vk_obj.r1csGgPpzksnarkVerificationKey.beta_g2)
    vk_json["delta_g2"] = parse_hexadecimalPointBaseGroup2Affine(vk_obj.r1csGgPpzksnarkVerificationKey.delta_g2)
    vk_json["abc_g1"] = json.loads(vk_obj.r1csGgPpzksnarkVerificationKey.abc_g1)
    return vk_json


def parse_verification_key(vk_obj, zksnark):
    if zksnark == constants.PGHR13_ZKSNARK:
        return parse_verification_key_PGHR13(vk_obj)
    elif zksnark == constants.GROTH16_ZKSNARK:
        return parse_verification_key_GROTH16(vk_obj)
    else:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)


def write_verification_key(vk_obj, zksnark):
    """
    Writes the verification key (object) in a json file
    """
    vk_json = parse_verification_key(vk_obj, zksnark)
    setup_dir = get_trusted_setup_dir()
    filename = os.path.join(setup_dir, "vk.json")
    with open(filename, 'w') as outfile:
        json.dump(vk_json, outfile)


def make_proofInputs(root, joinsplit_inputs, joinsplit_outputs, public_input_value, public_output_value, hsig, phi):
    return prover_pb2.ProofInputs(
        root=root,
        jsInputs=joinsplit_inputs,
        jsOutputs=joinsplit_outputs,
        inPubValue=public_input_value,
        outPubValue=public_output_value,
        hSig=hsig,
        phi=phi
    )


def parse_proof_PGHR13(proof_obj):
    proof_json = {}
    proof_json["a"] = parse_hexadecimalPointBaseGroup1Affine(proof_obj.r1csPpzksnarkExtendedProof.a)
    proof_json["a_p"] = parse_hexadecimalPointBaseGroup1Affine(proof_obj.r1csPpzksnarkExtendedProof.aP)
    proof_json["b"] = parse_hexadecimalPointBaseGroup2Affine(proof_obj.r1csPpzksnarkExtendedProof.b)
    proof_json["b_p"] = parse_hexadecimalPointBaseGroup1Affine(proof_obj.r1csPpzksnarkExtendedProof.bP)
    proof_json["c"] = parse_hexadecimalPointBaseGroup1Affine(proof_obj.r1csPpzksnarkExtendedProof.c)
    proof_json["c_p"] = parse_hexadecimalPointBaseGroup1Affine(proof_obj.r1csPpzksnarkExtendedProof.cP)
    proof_json["h"] = parse_hexadecimalPointBaseGroup1Affine(proof_obj.r1csPpzksnarkExtendedProof.h)
    proof_json["k"] = parse_hexadecimalPointBaseGroup1Affine(proof_obj.r1csPpzksnarkExtendedProof.k)
    proof_json["inputs"] = json.loads(proof_obj.r1csPpzksnarkExtendedProof.inputs)
    return proof_json


def parse_proof_GROTH16(proof_obj):
    proof_json = {}
    proof_json["a"] = parse_hexadecimalPointBaseGroup1Affine(proof_obj.r1csGgPpzksnarkExtendedProof.a)
    proof_json["b"] = parse_hexadecimalPointBaseGroup2Affine(proof_obj.r1csGgPpzksnarkExtendedProof.b)
    proof_json["c"] = parse_hexadecimalPointBaseGroup1Affine(proof_obj.r1csGgPpzksnarkExtendedProof.c)
    proof_json["inputs"] = json.loads(proof_obj.r1csGgPpzksnarkExtendedProof.inputs)
    return proof_json


def parse_proof(proof_obj, zksnark):
    if zksnark == constants.PGHR13_ZKSNARK:
        return parse_proof_PGHR13(proof_obj)
    elif zksnark == constants.GROTH16_ZKSNARK:
        return parse_proof_GROTH16(proof_obj)
    else:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)


def get_proof_joinsplit_2_by_2(
        grpc_endpoint,
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
    input_nullifier0 = compute_nullifier(input_note0, sender_ask)
    input_nullifier1 = compute_nullifier(input_note1, sender_ask)
    js_inputs = [
        create_joinsplit_input(
            mk_path0, input_address0, input_note0, sender_ask, input_nullifier0),
        create_joinsplit_input(
            mk_path1, input_address1, input_note1, sender_ask, input_nullifier1)
    ]

    random_seed = gen_signature_randomness()
    # Generate (joinsplit_pub_key, joinSplitPrivKey) key pair
    joinsplit_keypair = gen_one_time_schnorr_vk_sk_pair()
    h_sig = compute_h_sig(random_seed, input_nullifier0, input_nullifier1, joinsplit_keypair["vk"])
    phi = gen_transaction_randomness()

    output_note0, output_note1 = create_zeth_notes(
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

    proof_input = make_proofInputs(mk_root, js_inputs, js_outputs, public_in_value, public_out_value, h_sig, phi)
    proof_obj = get_proof(grpc_endpoint, proof_input)
    proof_json = parse_proof(proof_obj, zksnark)

    # We return the zeth notes to be able to spend them later
    # and the proof used to create them
    return (output_note0, output_note1, proof_json, joinsplit_keypair)
