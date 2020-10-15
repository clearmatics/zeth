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

// Implementation of MiMC hash targetting BLS12-377 Fr. This means:
//   r = 8444461749428370424248824938781546531375899335154063827935233455917409239041
//   d (exponent) = 11, so that 1 == gcd(d, r-1)
//   rounds = 73
//
// See MiMC7.sol for details.
library MiMC11
{
    function hash(bytes32 x, bytes32 y) internal pure returns(bytes32 out)
    {
        // Round function (see [AGRRT16]):
        //   F_i(a, key, rc_i) -> a^11 + key + rc
        //
        // where:
        //     rc_0 = 0
        //     rc_1 = keccak(seed)
        //     rc_i = keccak(rc_{i-1}), for i = 2, ...

        assembly
        {
            let r := 8444461749428370424248824938781546531375899335154063827935233455917409239041

            // Perform round 0, in which rc = 0
            let a := addmod(x, y, r)
            let a2 := mulmod(a, a, r)
            let a4 := mulmod(a2, a2, r)
            a := mulmod(mulmod(mulmod(a4, a4, r), a2, r), a, r)

            // Write round constant seed to pad at 0x00, where keccak256 will
            // be applied iteratively
            mstore(0x0, 0xdec937b7fa8db3de380427a8cc947bfab68514522c3439cfa2e9965509836814)

            for {let i := 0} slt(i, 72) {i := add(i,1)} {

                // Compute rc_i, and store it back in the pad
                let roundConstant := keccak256(0x0, 32)
                mstore(0x0, roundConstant)

                // Apply F_i
                a := addmod(addmod(a, roundConstant, r), y, r)
                a2 := mulmod(a, a, r)
                a4 := mulmod(a2, a2, r)
                a :=  mulmod(mulmod(mulmod(a4, a4, r), a2, r), a, r)
            }

            // Sum output with key, as described in [AGRRT16].
            a := addmod(a, y, r)

            // Myjaguchi-Prenell OWCF is then applied, which adds the key and
            // message to the output of MiMC.
            out := addmod(addmod(a, x, r), y, r)
        }
    }
}
