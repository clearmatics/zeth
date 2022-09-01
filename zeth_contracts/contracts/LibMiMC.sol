// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

/// Reference papers:
///
/// \[AGRRT16]:
/// "MiMC: Efficient Encryption and Cryptographic Hashing with Minimal
/// Multiplicative Complexity", Martin Albrecht, Lorenzo Grassi, Christian
/// Rechberger, Arnab Roy, and Tyge Tiessen, ASIACRYPT 2016,
/// <https://eprint.iacr.org/2016/492.pdf>
///
/// "One-way compression function"
/// Section: "Miyaguchi–Preneel"
// solhint-disable-next-line max-line-length
/// <https://en.wikipedia.org/wiki/One-way_compression_function#Miyaguchi%E2%80%93Preneel>
///
/// \[ZETHSPEC]:
/// "Zeth Protocol Specification", Clearmatics R&D,
/// <https://github.com/clearmatics/zeth-specifications>
library LibMiMC
{
    function _hashAltBN128(bytes32 x, bytes32 y)
        internal
        pure
        returns (bytes32 out) {
        // Use exponent 17 over 65 rounds (see [ZETHSPEC])
        return _hash_e17(
            x,
            y,
            // solhint-disable-next-line max-line-length
            21888242871839275222246405745257275088548364400416034343698204186575808495617,
            65);
    }

    function _hashBLS12_377(bytes32 x, bytes32 y)
        internal
        pure
        returns (bytes32 out) {
        // Use exponent 17 over 62 rounds (see [ZETHSPEC])
        return _hash_e17(
            x,
            y,
            // solhint-disable-next-line max-line-length
            8444461749428370424248824938781546531375899335154063827935233455917409239041,
            62);
    }

    function _hash_e17(bytes32 x, bytes32 y, uint256 r, uint8 rounds)
        private
        pure
        returns (bytes32 out) {
        // See [AGRRT16] and [ZETHSPEC]:
        //   The round function is:
        //     F_i(a, key, rc_i) -> a^17 + key + rc
        //
        //   where:
        //     rc_0 = 0
        //     rc_1 = keccak(seed)
        //     rc_i = keccak(rc_{i-1}), for i = 2, ...
        //
        // a is initialized as x, and key is set y

        assembly {

            // Perform round 0 with x + y (rc = 0 in first round)
            let a := addmod(x, y, r)
            let a2 := mulmod(a, a, r)
            let a4 := mulmod(a2, a2, r)
            let a8 := mulmod(a4, a4, r)
            a := mulmod(mulmod(a8, a8, r), a, r)

            // Write round constant seed to pad at 0x00, where keccak256 will
            // be applied iteratively
            // solhint-disable-next-line max-line-length
            mstore(0x0, 0xdec937b7fa8db3de380427a8cc947bfab68514522c3439cfa2e9965509836814)

            rounds := sub(rounds, 1)
            for {let j := 0} slt(j, rounds) {j := add(j,1)} {

                // roundConstant = H(roundConstant);
                // Derive the (round) constants by iterative hash on the seed
                let roundConstant := keccak256(0x0, 32)
                mstore(0x0, roundConstant)

                // a = (outPermutation + roundConstant + key) ^ 7 mod r
                a := addmod(addmod(a, roundConstant, r), y, r)
                a2 := mulmod(a, a, r)
                a4 := mulmod(a2, a2, r)
                a8 := mulmod(a4, a4, r)
                a := mulmod(mulmod(a8, a8, r), a, r)
            }

            // In MiMC, the final round output is summed with the round key
            a := addmod(a, y, r)

            // Myjaguchi-Preneel OWCF is then applied, which adds the key and
            // message to the output of MiMC.
            out := addmod(addmod(a, x, r), y, r)
        }
    }
}
