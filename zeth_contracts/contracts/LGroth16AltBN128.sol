// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

library LGroth16AltBN128
{
    // The structure of the verification key differs from the reference paper.
    // It doesn't contain any element of GT, but only elements of G1 and G2
    // (the source groups). This is due to the lack of precompiled contract to
    // manipulate elements of the target group GT on Ethereum. Note that Beta
    // and Delta are negated to avoid having to perform point negations in
    // contract code.

    // Used by client code to verify that inputs are in the correct field.
    uint256 internal constant _PRIME_R =
        // solhint-disable-next-line max-line-length
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Fr elements and Fq elements can be held in a single uint256. Therefore
    // G1 elements require 2 uint256s. G2 elements have coordinates in Fp2, and
    // therefore occupy 4 uint256s. Based on this, the offsets and slot numbers
    // are given below.

    // VerifyingKey:
    //     uint256[2] Alpha;       // slots 0x00, 0x01
    //     uint256[4] Minus_Beta;  // slots 0x02, 0x03, 0x04, 0x05
    //     uint256[4] Minus_Delta; // slots 0x06, 0x07, 0x08, 0x09
    //     uint256[] ABC;          // slot 0x0a (each entry uses 2 words)

    // Proof:
    //
    //     uint256[2] a,              (offset 00 - 0x00)
    //     uint256[4] b,              (offset 02 - 0x02)
    //     uint256[2] c,              (offset 06 - 0x06)
    //     <end>                      (offset 08 - 0x08)

    function _verify(
        uint256[] storage vk,
        uint256[] memory proof,
        uint256[] memory input
    )
        internal
        returns (bool)
    {
        require(proof.length == 8, "Proof size invalid (ALT-BN128)");

        // Compute the number of inputs expected, based on the verification key
        // size. (-1 because the VK contains the base point corresponding to a
        // virtual first input of value 1).
        uint256 numInputs = ((vk.length - 0x0a) / 2) - 1;
        require(
            input.length == numInputs,
            "Input length differs from expected");

        // Ensure that all inputs belong to the scalar field.
        for (uint256 i = 0 ; i < numInputs; i++) {
            require(input[i] < _PRIME_R, "Input is not in scalar field");
        }

        // 1. Compute the linear combination
        //   vk_x = \sum_{i=0}^{l} a_i * vk.ABC[i], vk_x in G1.
        //
        // ORIGINAL CODE:
        //   LPairing.G1Point memory vk_x = vk.ABC[0]; // a_0 = 1
        //   for (uint256 i = 0; i < input.length; i++) {
        //       vk_x =
        //           LPairing._addG1(vk_x,
        //               LPairing._scalarMulG1(vk.ABC[i + 1], input[i]));
        //   }
        //
        // The linear combination loop was the biggest cost center of the mixer
        // contract. The following assembly block removes a lot of unnecessary
        // memory usage and data copying, but relies on the structure of
        // storage data.
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
        //  ready to call bn256ScalarMul(in: 0x40, out: 0x40). This gives:
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

        // Memory scratch pad, large enough to accomodate the above layout.
        uint256[24] memory pad;
        bool success = true;
        uint256 vk_slot_num;
        assembly {

            let g := sub(gas(), 2000)

            // Compute starting slot of vk data.
            mstore(pad, vk.slot)
            vk_slot_num := keccak256(pad, 0x20)
            let abc_slot_num := add(vk_slot_num, 0x0a)

            // Compute input array bounds (layout: <len>,elem_0,elem_1...)
            let input_i := add(input, 0x20)
            let input_end := add(input_i, mul(0x20, mload(input)))

            // Initialize pad[0] with abc[0]
            mstore(pad, sload(abc_slot_num))
            abc_slot_num := add(abc_slot_num, 1)
            mstore(add(pad, 0x20), sload(abc_slot_num))
            abc_slot_num := add(abc_slot_num, 1)

            // Location within pad to do scalar mul operation
            let mul_in := add(pad, 0x40)

            // Iterate over all inputs / ABC values
            for
                { }
                lt(input_i, input_end)
                { }
            {
                // Copy abc[i+1] into mul_in, incrementing abc_slot_num
                mstore(mul_in, sload(abc_slot_num))
                abc_slot_num := add(abc_slot_num, 1)
                mstore(add(mul_in, 0x20), sload(abc_slot_num))
                abc_slot_num := add(abc_slot_num, 1)

                // Copy input[i] into mul_in + 0x40, and increment index_i
                mstore(add(mul_in, 0x40), mload(input_i))
                input_i := add(input_i, 0x20)

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
        //       e(vk.Alpha, vk.Beta) * e(vk_x, g2) * e(Proof.C, vk.Delta)
        // where:
        // - e: G_1 x G_2 -> G_T is a bilinear map
        // - `*`: denote the group operation in G_T

        // Assembly below fills out pad and calls bn256Pairing, performing a
        // check of the form:
        //
        //   e(vk_x, -g2) * e(vk.Alpha, vk.Minus_Beta) *
        //       e(negate(Proof.A), Proof.B) * e(Proof.C, vk.Minus_Delta) == 1
        //
        // See LPairing.pairing().
        // Note terms have been re-ordered since vk_x is already at offset
        // 0x00. Memory is laid out:
        //
        //   0x0300
        //   0x0280 - verifyKey.Minus_Delta in G2
        //   0x0240 - proof.C in G1
        //   0x01c0 - Proof.B in G2
        //   0x0180 - Proof.A in G1
        //   0x0100 - vk.Minus_Beta in G2
        //   0x00c0 - vk.Alpha in G1
        //   0x0040 - -g2 in G2
        //   0x0000 - vk_x in G1  (Already present, by the above)

        assembly {

            // Write -g2 (G2 generator), from offset 0x40. (These values are
            // computed by the ec_operations_data_test).
            mstore(
                add(pad, 0x040),
                // solhint-disable-next-line max-line-length
                0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2)
            mstore(
                add(pad, 0x060),
                // solhint-disable-next-line max-line-length
                0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed)
            mstore(
                add(pad, 0x080),
                // solhint-disable-next-line max-line-length
                0x275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec)
            mstore(
                add(pad, 0x0a0),
                // solhint-disable-next-line max-line-length
                0x1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d)

            // Write vk.Alpha, vk.Minus_Beta (first 6 uints from verifyKey)
            // from offset 0x0c0.
            mstore(add(pad, 0x0c0), sload(vk_slot_num))
            mstore(add(pad, 0x0e0), sload(add(vk_slot_num, 1)))
            mstore(add(pad, 0x100), sload(add(vk_slot_num, 2)))
            mstore(add(pad, 0x120), sload(add(vk_slot_num, 3)))
            mstore(add(pad, 0x140), sload(add(vk_slot_num, 4)))
            mstore(add(pad, 0x160), sload(add(vk_slot_num, 5)))

            // Write Proof.A and Proof.B from offset 0x180.
            proof := add(proof, 0x20)
            mstore(add(pad, 0x180), mload(proof))
            mstore(add(pad, 0x1a0), mload(add(proof, 0x20)))
            mstore(add(pad, 0x1c0), mload(add(proof, 0x40)))
            mstore(add(pad, 0x1e0), mload(add(proof, 0x60)))
            mstore(add(pad, 0x200), mload(add(proof, 0x80)))
            mstore(add(pad, 0x220), mload(add(proof, 0xa0)))

            // Proof.C and verifyKey.Minus_Delta from offset 0x240.
            mstore(add(pad, 0x240), mload(add(proof, 0xc0)))
            mstore(add(pad, 0x260), mload(add(proof, 0xe0)))
            mstore(add(pad, 0x280), sload(add(vk_slot_num, 6)))
            mstore(add(pad, 0x2a0), sload(add(vk_slot_num, 7)))
            mstore(add(pad, 0x2c0), sload(add(vk_slot_num, 8)))
            mstore(add(pad, 0x2e0), sload(add(vk_slot_num, 9)))

            success := call(sub(gas(), 2000), 8, 0, pad, 0x300, pad, 0x20)
        }

        require(
            success,
            "Call to bn256Add, bn256ScalarMul or bn256Pairing failed");
        return 1 == pad[0];
    }
}
