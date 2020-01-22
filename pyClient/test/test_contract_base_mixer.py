#!/usr/bin/env python3
import test_commands.mock as mock
import zeth.constants as constants
import zeth.joinsplit

from typing import Any

# Mixer variables
size_value = 64  # pylint: disable=no-member,invalid-name
digest_length = 256  # pylint: disable=no-member,invalid-name
field_capacity = 253  # pylint: disable=no-member,invalid-name
js_in = 2  # pylint: disable=no-member,invalid-name
js_out = 2  # pylint: disable=no-member,invalid-name
packing_residue_length = digest_length % field_capacity \
    # pylint: disable=no-member,invalid-name
if digest_length <= field_capacity:
    packing_residue_length = 0
# offset = 2 * size_value + packing_residue_length
length_bit_residual = 2 * size_value + packing_residue_length * \
    (1 + 2 * js_in + js_out)  # pylint: disable=no-member,invalid-name
# nb_field_residual = math.ceil(length_bit_residual / field_capacity)

# The variable inputs represents a dummy primary input array,
# it is structured as follows,
# inputs =
#   rt || {sn}_1,2 || {cm}_1,2 || h_sig || {h}_1,2 || residual_bits
# residual_bits =
#   v_in || v_out || h_sig || {sn}_1,2  || {cm}_1,2  || {h}_1,2
# We set dummy values for all variables but residual_bits as follows:
# residual_bits = 713623846352979940490457358497079434602616037, or in bits
# 1-4:   00000000 00000000 00000000 00000000
# 5-8:   00000000 00000000 00000000 00000000
# 9-12:  00000000 00000000 00000000 00000000
# 13-16: 00000000 00011111 11111111 11111111
# 17-20: 11111111 11111111 11111111 11111111
# 21-24: 11111111 11100000 00000000 00000000
# 25-28: 00000000 00000000 00000000 00000000
# 29-32: 00000000 00011100 00010100 11100101
# This corresponds to
# v_in  = 0xFFFFFFFFFFFFFFFF
# v_out = 0x0000000000000000
# h_sig = 111
# sn_0  = 000
# sn_1  = 001
# cm_0  = 010
# cm_1  = 011
# h_0   = 100
# h_1   = 101
# The values were set to be easily distinguishable.
inputs = [
    0,  # root
    1,  # sn_0
    1,  # sn_1
    2,  # cm_0
    2,  # cm_1
    3,  # h_sig
    4,  # h_0
    4,  # h_1
    713623846352979940490457358497079434602616037] \
        # residual bits ; pylint: disable=no-member,invalid-name


def test_extract(mixer_instance: Any) -> int:
    # This test checks that we extract the right values
    # for {sn}, {cm} and {h} regardless of whether
    # the bits are located in the same byte
    # or two different ones (c.f. residual_bits above).
    print("--- testing ", "test_extract")

    start = 0
    for i in range(2*js_in+js_out):
        res = mixer_instance.functions.extract_extra_bits(
            start,
            packing_residue_length,
            inputs
            ).call()
        if int.from_bytes(res, byteorder="big") != i:
            print("ERROR: extracted wrong value")
            return 0
        start += packing_residue_length
    return 1


def test_assemble_nullifiers(mixer_instance: Any) -> int:
    # Test retrieving nullifiers
    print("--- testing ", "test_assemble_nullifiers")
    for i in range(js_in):
        res = mixer_instance.functions.assemble_nullifier(i, inputs).call()
        val = int.from_bytes(res, byteorder="big")
        expected_val = 2**(256-1) + int(("{0:03b}".format(i))[::-1], 2)
        if val != expected_val:
            print("ERROR: extracted wrong nullifier")
            print("expected:", expected_val, i)
            print("got:", val, i)
            return 0
    return 1


def test_assemble_commitments(mixer_instance: Any) -> int:
    # Test retrieving commitments
    print("--- testing ", "test_assemble_commitments")
    for i in range(js_out):
        res = mixer_instance.functions.assemble_commitment(i, inputs).call()
        val = int.from_bytes(res, byteorder="big")
        expected_val = 2**(256-1-1) + int(("{0:03b}".format(2+i))[::-1], 2)
        if val != expected_val:
            print("ERROR: extracted wrong commitment")
            print("expected:", expected_val, i)
            print("got:", val, i)
            return 0
    return 1


def test_extract_negative_start(mixer_instance: Any) -> int:
    # Tests on input start
    # We check that a negative start returns an error
    print("--- testing ", "test_extract_negative_start")
    try:
        res = mixer_instance.functions.extract_extra_bits(
            -1,
            packing_residue_length,
            inputs
            ).call()
        print(res)
    except Exception:
        pass
    else:
        print("ERROR: negative start value accepted")
        return 0
    return 1


def test_extract_high_start(mixer_instance: Any) -> int:
    # We check that a high start value returns an error
    # (start must be comprised in [0, `length_bit_residual`-`offset`])
    print("--- testing ", "test_extract_high_start")
    try:
        res = mixer_instance.functions.extract_extra_bits(
            length_bit_residual,
            packing_residue_length,
            inputs
            ).call()
        print(res)
    except Exception:
        pass
    else:
        print("ERROR: high start value accepted")
        return 0
    return 1


def test_extract_negative_length(mixer_instance: Any) -> int:
    # Tests on input length
    # We check that a negative length returns an error
    print("--- testing ", "test_extract_negative_length")
    try:
        res = mixer_instance.functions.extract_extra_bits(
            0,
            -1,
            inputs
            ).call()
        print(res)
    except Exception:
        pass
    else:
        print("ERROR: negative start value accepted")
        return 0
    return 1


def test_extract_null_length(mixer_instance: Any) -> int:
    # We check that a null length returns 0
    print("--- testing ", "test_extract_null_length")
    res = mixer_instance.functions.extract_extra_bits(
        0,
        0,
        inputs
        ).call()
    if int.from_bytes(res, byteorder="big") != 0:
        print("ERROR: null length accepted")
        return 0
    return 1


def test_extract_high_length(mixer_instance: Any) -> int:
    # We check that a high length returns an error
    # (length must be comprised in [0,8])
    print("--- testing ", "test_extract_high_length")
    try:
        res = mixer_instance.functions.extract_extra_bits(
            0,
            10,
            inputs
            ).call()
        print(res)
    except Exception:
        pass
    else:
        print("ERROR: high length accepted")
        return 0
    return 1


def test_extract_short_primary_inputs(mixer_instance: Any) -> int:
    # Tests on input primary_inputs
    # We check that a short primary value return an error
    # (shorter than `nb_field_residual`)
    print("--- testing ", "test_extract_short_primary_inputs")
    try:
        primary_inputs = inputs[:7]
        res = mixer_instance.functions.extract_extra_bits(
            length_bit_residual,
            packing_residue_length,
            primary_inputs
            ).call()
        print(res)
    except Exception:
        pass
    else:
        print("ERROR: shorter primary inputs accepted")
        return 0
    return 1


def test_extract_long_primary_inputs(mixer_instance: Any) -> int:
    # We check that a long primary value return an error
    # (longer than `nb_field_residual`)
    print("--- testing ", "test_extract_long_primary_inputs")
    try:
        primary_inputs = inputs
        primary_inputs.append(10)
        res = mixer_instance.functions.extract_extra_bits(
            length_bit_residual,
            packing_residue_length,
            primary_inputs
            ).call()
        print(res)
    except Exception:
        pass
    else:
        print("ERROR: longer primary inputs accepted")
        return 0
    return 1


def test_extract_empty_primary_inputs(mixer_instance: Any) -> int:
    # We check that a empty primary value return an error
    print("--- testing ", "test_extract_empty_primary_inputs")
    try:
        res = mixer_instance.functions.extract_extra_bits(
            length_bit_residual,
            packing_residue_length,
            []
            ).call()
        print(res)
    except Exception:
        pass
    else:
        print("ERROR: empty primary inputs accepted")
        return 0
    return 1


def main() -> None:
    print("-------------------- Evaluating BaseMixer.sol --------------------")

    zksnark = zeth.zksnark.get_zksnark_provider(zeth.utils.parse_zksnark_arg())

    web3, eth = mock.open_test_web3()

    # Ethereum addresses
    deployer_eth_address = eth.accounts[0]

    prover_client = mock.open_test_prover_client()

    # Deploy Zeth contracts
    zeth_client = zeth.joinsplit.ZethClient.deploy(
        web3,
        prover_client,
        constants.ZETH_MERKLE_TREE_DEPTH,
        deployer_eth_address,
        zksnark)

    mixer_instance = zeth_client.mixer_instance

    # We can now call the instance and test its functions.
    print("[INFO] 4. Running tests")
    result = 1
    result *= test_extract(mixer_instance)
    result *= test_assemble_commitments(mixer_instance)
    result *= test_assemble_nullifiers(mixer_instance)

    result *= test_extract_negative_start(mixer_instance)
    result *= test_extract_high_start(mixer_instance)

    result *= test_extract_negative_length(mixer_instance)
    result *= test_extract_null_length(mixer_instance)
    result *= test_extract_high_length(mixer_instance)

    result *= test_extract_short_primary_inputs(mixer_instance)
    result *= test_extract_long_primary_inputs(mixer_instance)
    result *= test_extract_empty_primary_inputs(mixer_instance)

    if result:
        print("base_mixer tests PASS")


if __name__ == '__main__':
    main()
