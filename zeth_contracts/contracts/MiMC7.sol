// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

library MiMC7
{
    /*
     * Reference papers:
     *
     * \[AGRRT16]:
     * "MiMC: Efficient Encryption and Cryptographic Hashing with Minimal
     * Multiplicative Complexity", Martin Albrecht, Lorenzo Grassi, Christian
     * Rechberger, Arnab Roy, and Tyge Tiessen, ASIACRYPT 2016,
     * <https://eprint.iacr.org/2016/492.pdf>
     *
     * "One-way compression function"
     * Section: "Miyaguchi–Preneel"
     * <https://en.wikipedia.org/wiki/One-way_compression_function#Miyaguchi%E2%80%93Preneel>
     **/
    function hash(bytes32 x, bytes32 y) internal pure returns (bytes32 out) {
        assembly {
            // Use scratch space (0x00) for roundConstant. Must use memory since
            // keccak256 is iteratively applied. Start with seed =
            // keccak256("clearmatics_mt_seed")
            mstore(0x0, 0xdec937b7fa8db3de380427a8cc947bfab68514522c3439cfa2e9965509836814)

            // See:
            // https://github.com/ethereum/go-ethereum/blob/master/crypto/bn256/cloudflare/constants.go#L23
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617

            // y will be use used as round key of the block cipher as defined by
            // Miyaguchi-Prenel construction
            let key := y

            // Round function f(message) = (message + key + roundConstant)^d
            // d (= exponent) = 7; #rounds = 91
            //
            // Note on the exponent: gcd(7, r - 1) = 1 which confirms that the
            // monomial x^7 is a permutation in Fr. See: Proposition 1, Section
            // 4 and section 5; https://eprint.iacr.org/2016/492.pdf
            //
            // In the first round the constant is not used
            let outPermutation := x

            // a = outPermutation + roundConstant + key mod r
            let a := addmod(outPermutation, key, r)
            // a2 = a^2 mod r
            let a2 := mulmod(a, a, r)
            // outPermutation = a^7 mod r
            //   (x^7 is the permutation polynomial used)
            outPermutation := mulmod(mulmod(a2, a2, r), mulmod(a2, a, r), r)

            for {let j := 0} slt(j, 90) {j := add(j,1)} {
                // roundConstant = H(roundConstant);
                // we derive the (round) constants by iterative hash on the seed
                let roundConstant := keccak256(0x0, 32)
                mstore(0x0, roundConstant)
                // a = outPermutation + roundConstant + key mod r
                a := addmod(addmod(outPermutation, roundConstant, r), key, r)
                // a2 = a^2 mod r
                a2 := mulmod(a, a, r)
                // outPermutation = a^7 mod r
                //   (x^7 is the permutation polynomial used)
                outPermutation :=  mulmod(mulmod(mulmod(a2, a2, r), a2, r), a, r)
            }

            // Compute H_i from H_{i-1} to generate the round key for the next
            // entry in the input slice x.  In MiMC the output of the last round
            // is mixed with the round key: This corresponds to the
            // `outMiMCCipher = addmod(outPermutation, key, r)`.  And, the
            // Myjaguchi-Prenell OWCF is ran: `addmod(addmod(outMiMCCipher,
            // message, r), key, r)`.  Note that we have merged the key addition
            // ( +key ) of the last round of MiMC with the Myjaguchi-Prenell
            // step.
            out := addmod(addmod(addmod(outPermutation, key, r), x, r), key, r)
        }
    }
}
