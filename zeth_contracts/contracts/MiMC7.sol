// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

// Reference papers:
//
// \[AGRRT16]:
// "MiMC: Efficient Encryption and Cryptographic Hashing with Minimal
// Multiplicative Complexity", Martin Albrecht, Lorenzo Grassi, Christian
// Rechberger, Arnab Roy, and Tyge Tiessen, ASIACRYPT 2016,
// <https://eprint.iacr.org/2016/492.pdf>
//
// "One-way compression function"
// Section: "Miyaguchi–Preneel"
// <https://en.wikipedia.org/wiki/One-way_compression_function#Miyaguchi%E2%80%93Preneel>

library MiMC7
{
    function hash(bytes32 x, bytes32 y) internal pure returns (bytes32 out)
    {
        // See [AGRRT16]:
        //   The round function is:
        //     F_i(a, key, rc_i) -> a^7 + key + rc
        //
        //   where:
        //     rc_0 = 0
        //     rc_1 = keccak(seed)
        //     rc_i = keccak(rc_{i-1}), for i = 2, ...
        //
        // a is initialized as x, and key is set y

        assembly {

            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617

            // Perform round 0 with x + y (rc = 0 in first round)
            let a := addmod(x, y, r)
            let a2 := mulmod(a, a, r)
            a := mulmod(mulmod(mulmod(a2, a2, r), a2, r), a, r)

            // Write round constant seed to pad at 0x00, where keccak256 will
            // be applied iteratively
            mstore(0x0, 0xdec937b7fa8db3de380427a8cc947bfab68514522c3439cfa2e9965509836814)

            for {let j := 0} slt(j, 90) {j := add(j,1)} {

                // roundConstant = H(roundConstant);
                // we derive the (round) constants by iterative hash on the seed
                let roundConstant := keccak256(0x0, 32)
                mstore(0x0, roundConstant)

                // a = (outPermutation + roundConstant + key) ^ 7 mod r
                a := addmod(addmod(a, roundConstant, r), y, r)
                a2 := mulmod(a, a, r)
                a :=  mulmod(mulmod(mulmod(a2, a2, r), a2, r), a, r)
            }

            // In MiMC, the final round output is summed with the round key
            a := addmod(a, y, r)

            // Myjaguchi-Preneel OWCF is then applied, which adds the key and
            // message to the output of MiMC.
            out := addmod(addmod(a, x, r), y, r)
        }
    }
}
