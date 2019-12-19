// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

/*
 * Reference paper:
 *
 * \[Gro16]:
 * "On the Size of Pairing-based Non-interactive Arguments",
 * Jens Groth,
 * EUROCRYPT 2016,
 * <https://eprint.iacr.org/2016/260>
**/

import "./Pairing.sol";

// Groth16 Verifier contract
contract Groth16Verifier {
    using Pairing for *;

    // The structure of the verification key differs from the reference paper.
    // It doesn't contain any element of GT, but only elements of G1 and G2 (the
    // source groups). This is due to the lack of precompiled contract to
    // manipulate elements of the target group GT on Ethereum.
    struct VerifyingKey {
        Pairing.G1Point Alpha;      // slots 0x00, 0x01
        Pairing.G2Point Beta;       // slots 0x02, 0x03, 0x04, 0x05
        Pairing.G2Point Delta;      // slots 0x06, 0x07, 0x08, 0x09
        Pairing.G1Point[] ABC;      // slot 0x0a
    }

    // Internal Proof structure.  Avoids reusing the G1 and G2 structs, since
    // these cause extra pointers in memory, and complexity passing the data to
    // precompiled contracts.
    struct Proof {
        // Pairing.G1Point A;
        uint A_X;
        uint A_Y;
        // Pairing.G2Point B;
        uint B_X0;
        uint B_X1;
        uint B_Y0;
        uint B_Y1;
        // Pairing.G1Point C;
        uint C_X;
        uint C_Y;
    }

    VerifyingKey verifyKey;

    event LogVerifier(string);

    constructor(
        uint[2] memory Alpha,
        uint[2] memory Beta1,
        uint[2] memory Beta2,
        uint[2] memory Delta1,
        uint[2] memory Delta2,
        uint[] memory ABC_coords
    ) public {
        verifyKey.Alpha = Pairing.G1Point(Alpha[0], Alpha[1]);
        verifyKey.Beta = Pairing.G2Point(Beta1[0], Beta1[1], Beta2[0], Beta2[1]);
        verifyKey.Delta = Pairing.G2Point(
            Delta1[0], Delta1[1], Delta2[0], Delta2[1]);

        // The `ABC` are elements of G1 (and thus have 2 coordinates in the
        // underlying field). Here, we reconstruct these group elements from
        // field elements (ABC_coords are field elements)
        uint i;
        while(verifyKey.ABC.length != ABC_coords.length/2) {
            verifyKey.ABC.push(Pairing.G1Point(ABC_coords[i], ABC_coords[i+1]));
            i += 2;
        }
    }

    function verify(
        uint[] memory input, Proof memory proof) internal returns (uint) {

        // `input.length` = size of the instance = l (see notations in the
        // reference paper).  We have coefficients indexed in the range[1..l],
        // where l is the instance size, and we define a_0 = 1. This is the
        // reason we need to check that: input.length + 1 == vk.ABC.length (the
        // +1 accounts for a_0). This equality is a strong consistency check
        // (len(givenInputs) needs to equal expectedInputSize (not less))
        require(
            input.length + 1 == verifyKey.ABC.length,
            "Input length differs from expected");

        // A memory scratch pad
        uint[24] memory pad;

        // 1. Compute the linear combination
        //   vk_x = \sum_{i=0}^{l} a_i * vk.ABC[i], vk_x in G1.
        //
        // ORIGINAL CODE:
        //   Pairing.G1Point memory vk_x = vk.ABC[0]; // a_0 = 1
        //   for (uint i = 0; i < input.length; i++) {
        //       vk_x = Pairing.add(vk_x, Pairing.mul(vk.ABC[i + 1], input[i]));
        //   }
        //
        // The linear combination loop was the biggest cost center of the mixer
        // contract.  The following assembly block removes a lot of unnecessary
        // memory usage and data copying, but relies on the structure of storage
        // data.
        //
        // `pad` is layed out as follows, (so that calls to precompiled
        // contracts can be done with minimal data copying)
        //
        //  OFFSET  USAGE
        //   0x20    accum_y
        //   0x00    accum_x

        // In each iteration, copy scalar multiplicaation data to 0x40+
        //
        //  OFFSET  USAGE
        //   0x80    input_i   --
        //   0x60    abc_y      | compute abc[i+1] * input[i] in-place
        //   0x40    abc_x     --
        //   0x20    accum_y
        //   0x00    accum_x
        //
        //  ready to call bn256ScalarMul(in: 0x40, out: 0x40).  This results in:
        //
        //  OFFSET  USAGE
        //   0x80
        //   0x60    input_i * abc_y  --
        //   0x40    input_i * abc_x   |  accum = accum + input[i] * abc[i+1]
        //   0x20    accum_y           |
        //   0x00    accum_x          --
        //
        //  ready to call bn256Add(in: 0x00, out: 0x00) to update accum_x,
        //  accum_y in place.

        bool success = true;
        assembly {

            let g := sub(gas, 2000)

            // Compute slot of ABC[0], using pad[0] as a temporary
            mstore(pad, add(verifyKey_slot, 10))
            let abc_slot := keccak256(pad, 32)

            // Compute input array bounds (layout: <len>,elem_0,elem_1...)
            let input_i := add(input, 0x20)
            let input_end := add(input_i, mul(0x20, mload(input)))

            // Initialize pad[0] with abc[0]
            mstore(pad, sload(abc_slot))
            mstore(add(pad, 0x20), sload(add(abc_slot, 1)))
            abc_slot := add(abc_slot, 2)

            // Location within pad to do scalar mul operation
            let mul_in := add(pad, 0x40)

            // Iterate over all inputs / ABC values
            for
            { }
            lt(input_i, input_end)
            {
                abc_slot := add(abc_slot, 2)
                input_i := add(input_i, 0x20)
            }
            {
                // Copy abc[i+1] into mul_in, incrementing abc
                mstore(mul_in, sload(abc_slot))
                mstore(add(mul_in, 0x20), sload(add(abc_slot, 1)))

                // Copy input[i] into mul_in + 0x40, and increment index_i
                mstore(add(mul_in, 0x40), mload(input_i))

                // bn256ScalarMul and bn256Add can be done with no copying
                let s1 := call(g, 7, 0, mul_in, 0x60, mul_in, 0x40)
                let s2 := call(g, 6, 0, pad, 0x80, pad, 0x40)
                success := and(success, and(s1, s2))
            }
        }

        require(
            success,
            "Call to the bn256Add or bn256ScalarMul precompiled failed");

        // 2. The verification check:
        //   e(Proof.A, Proof.B) =
        //       e(vk.Alpha, vk.Beta) * e(vk_x, P2) * e(Proof.C, vk.Delta)
        // where:
        // - e: G_1 x G_2 -> G_T is a bilinear map
        // - `*`: denote the group operation in G_T

        // ORIGINAL CODE:
        //   bool res = Pairing.pairingProd4(
        //       Pairing.negate(Pairing.G1Point(proof.A_X, proof.A_Y)),
        //       Pairing.G2Point(proof.B_X0, proof.B_X1, proof.B_Y0, proof.B_Y1),
        //       verifyKey.Alpha, verifyKey.Beta,
        //       vk_x, Pairing.P2(),
        //       Pairing.G1Point(proof.C_X, proof.C_Y),
        //       verifyKey.Delta);
        //   if (!res) {
        //       return 0;
        //   }
        //   return 1;

        // Assembly below fills out pad and calls bn256Pairing, performing a
        // check of the form:
        //
        //   e(vk_x, P2) * e(vk.Alpha, vk.Beta) *
        //       e(negate(Proof.A), Proof.B) * e(Proof.C, vk.Delta) == 1
        //
        // See Pairing.pairing().  Note terms have been re-ordered since vk_x is
        // already at offset 0x00.  Memory is laid out:
        //
        //   0x0300
        //   0x0280 - verifyKey.Delta in G2
        //   0x0240 - proof.C in G1
        //   0x01c0 - Proof.B in G2
        //   0x0180 - negate(Proof.A) in G1
        //   0x0100 - vk.Beta in G2
        //   0x00c0 - vk.Alpha in G1
        //   0x0040 - P2 in G2
        //   0x0000 - vk_x in G1  (Already present, by the above)

        assembly {

            // Write P2, from offset 0x40.  See Pairing for these values.
            mstore(
                add(pad, 0x040),
                11559732032986387107991004021392285783925812861821192530917403151452391805634)
            mstore(
                add(pad, 0x060),
                10857046999023057135944570762232829481370756359578518086990519993285655852781)
            mstore(
                add(pad, 0x080),
                4082367875863433681332203403145435568316851327593401208105741076214120093531)
            mstore(
                add(pad, 0x0a0),
                8495653923123431417604973247489272438418190587263600148770280649306958101930)

            // Write vk.Alpha, vk.Beta (first 6 uints from verifyKey) from
            // offset 0x0c0.
            mstore(add(pad, 0x0c0), sload(verifyKey_slot))
            mstore(add(pad, 0x0e0), sload(add(verifyKey_slot, 1)))
            mstore(add(pad, 0x100), sload(add(verifyKey_slot, 2)))
            mstore(add(pad, 0x120), sload(add(verifyKey_slot, 3)))
            mstore(add(pad, 0x140), sload(add(verifyKey_slot, 4)))
            mstore(add(pad, 0x160), sload(add(verifyKey_slot, 5)))

            // Write negate(Proof.A) and Proof.B from offset 0x180.
            mstore(add(pad, 0x180), mload(proof))
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583
            let proof_A_y := mload(add(proof, 0x20))
            mstore(add(pad, 0x1a0), sub(q, mod(proof_A_y, q)))
            mstore(add(pad, 0x1c0), mload(add(proof, 0x40)))
            mstore(add(pad, 0x1e0), mload(add(proof, 0x60)))
            mstore(add(pad, 0x200), mload(add(proof, 0x80)))
            mstore(add(pad, 0x220), mload(add(proof, 0xa0)))

            // Proof.C and verifyKey.Delta from offset 0x240.
            mstore(add(pad, 0x240), mload(add(proof, 0xc0)))
            mstore(add(pad, 0x260), mload(add(proof, 0xe0)))
            mstore(add(pad, 0x280), sload(add(verifyKey_slot, 6)))
            mstore(add(pad, 0x2a0), sload(add(verifyKey_slot, 7)))
            mstore(add(pad, 0x2c0), sload(add(verifyKey_slot, 8)))
            mstore(add(pad, 0x2e0), sload(add(verifyKey_slot, 9)))

            success := call(sub(gas, 2000), 8, 0, pad, 0x300, pad, 0x20)
        }

        require(
            success,
            "Call to bn256Add, bn256ScalarMul or bn256Pairing failed");
        return pad[0];
    }

    function verifyTx(
        uint[2] memory a,
        uint[4] memory b,
        uint[2] memory c,
        uint[] memory primaryInputs
    ) public returns (bool) {
        // Scalar field characteristic
        // solium-disable-next-line
        uint256 r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

        Proof memory proof;
        proof.A_X = a[0];
        proof.A_Y = a[1];
        proof.B_X0 = b[0];
        proof.B_X1 = b[1];
        proof.B_Y0 = b[2];
        proof.B_Y1 = b[3];
        proof.C_X = c[0];
        proof.C_Y = c[1];

        uint[] memory inputValues = new uint[](primaryInputs.length);
        for (uint i = 0; i < primaryInputs.length; i++) {
            // Make sure that all primary inputs lie in the scalar field
            require(
                primaryInputs[i] < r,
                "Input is not in scalar field"
            );
            inputValues[i] = primaryInputs[i];
        }

        uint verification_result = verify(inputValues, proof);
        if (verification_result != 1) {
            emit LogVerifier("Failed to verify the transaction");
            return false;
        }

        emit LogVerifier("Proof verification successfull");
        return true;
    }
}
