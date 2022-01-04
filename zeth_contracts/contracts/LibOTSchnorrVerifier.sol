// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

/// Reference paper:
///  \[Bel07]:
///  "Two-Tier Signatures, Strongly Unforgeable Signatures and Fiat-Shamir
///   without Random Oracles",
///  Mihir Bellare, Sarah Shoup,
///  International Workshop on Public Key Cryptography, 2007,
///  <https://eprint.iacr.org/2007/273.pdf>
library LibOTSchnorrVerifier {

    function _verify(
        uint256 vk0,
        uint256 vk1,
        uint256 vk2,
        uint256 vk3,
        uint256 sigma,
        bytes32 hashToBeSigned
    )
        internal
        returns (bool)
    {
        // Original code:
        //
        //   bytes32 h_bytes = sha256(
        //       abi.encodePacked(vk[2], vk[3], hashToBeSigned));
        //   uint256 h = uint256(h_bytes);
        //
        //   // X = g^{x}, where g is a generator of the cyclic group G
        //   LibPairing.G1Point memory X = LibPairing.G1Point(vk[0], vk[1]);
        //   // Y = g^{y}
        //   LibPairing.G1Point memory Y = LibPairing.G1Point(vk[2], vk[3]);
        //
        //   // S = g^{sigma}
        //   LibPairing.G1Point memory S =
        //       LibPairing._scalarMulG1(LibPairing._genG1(), sigma);
        //   // S_comp = g^{y + xh}
        //   LibPairing.G1Point memory S_comp =
        //       LibPairing._addG1(Y, LibPairing._scalarMulG1(X, h));
        //
        //   // Check that g^{sigma} == g^{y + xh}
        //   return (S.X == S_comp.X && S.Y == S_comp.Y);

        // Pad
        uint256[5] memory pad;

        assembly {

            let g := sub(gas(), 2000)

            // pad:
            //   0x40  hashToBeSigned
            //   0x20  Y[1]
            //   0x00  Y[0]
            // Compute sha256 into 0x40

            mstore(pad, vk2)
            mstore(add(pad, 0x20), vk3)
            mstore(add(pad, 0x40), hashToBeSigned)
            pop(call(g, 2, 0, pad, 0x60, add(pad, 0x80), 0x20))

            // pad:
            //   0x80  h = sha256(Y || hashToBeSigned)
            //   0x60
            //   0x40
            //   0x20  Y[1]
            //   0x00  Y[0]
            // Write X from 0x40 and call bn256ScalarMul(in: 0x40, out: 0x40)

            let x_location := add(pad, 0x40)
            mstore(x_location, vk0)
            mstore(add(x_location, 0x20), vk1)
            pop(call(g, 7, 0, x_location, 0x60, x_location, 0x40))

            // pad:
            //   0x60  h.X[1]
            //   0x40  h.X[0]
            //   0x20  Y[1]
            //   0x00  Y[0]
            // Call bn256Sum(in: 0x00, out: 0x00)

            pop(call(g, 6, 0, pad, 0x80, pad, 0x40))

            // pad:
            //   0x60
            //   0x40
            //   0x20  (Y + h.X)[1]
            //   0x00  (Y + h.X)[0]
            // copy _genG1 and sigma (see LibPairing.sol for values)

            mstore(add(pad, 0x40), 1)
            mstore(add(pad, 0x60), 2)
            mstore(add(pad, 0x80), sigma)

            // pad:
            //   0x80  sigma
            //   0x60  _genG1[1]
            //   0x40  _genG1[0]
            //   0x20  (Y + h.X)[1]
            //   0x00  (Y + h.X)[0]
            // call bn256ScalarMul(in: 0x40, out: 0x40)

            pop(call(g, 7, 0, x_location, 0x60, x_location, 0x40))

            // pad:
            //   0x60  sigma._genG1[1]
            //   0x40  sigma._genG1[0]
            //   0x20  (Y + h.X)[1]
            //   0x00  (Y + h.X)[0]
        }

        // compare
        return pad[0] == pad[2] && pad[1] == pad[3];
    }
}
