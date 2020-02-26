// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

// Several pairing-related utility functions.
//
// Precompiled contract details (bn256Add, bn256ScalarMul, bn256Pairing) can be
// found at the following links. Implementations:
//   https://github.com/ethereum/go-ethereum/blob/master/core/vm/contracts.go gas
// and costs:
//   https://github.com/ethereum/go-ethereum/blob/master/params/protocol_params.go

library Pairing {

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256 X0;
        uint256 X1;
        uint256 Y0;
        uint256 Y1;
    }

    // Return the generator of G1
    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    // Return the generator of G2
    function P2() internal pure returns (G2Point memory) {
        return G2Point(
            // solium-disable-next-line
            11559732032986387107991004021392285783925812861821192530917403151452391805634,
            // solium-disable-next-line
            10857046999023057135944570762232829481370756359578518086990519993285655852781,
            // solium-disable-next-line
            4082367875863433681332203403145435568316851327593401208105741076214120093531,
            // solium-disable-next-line
            8495653923123431417604973247489272438418190587263600148770280649306958101930);
    }

    // Return the negation of p, i.e. p.add(p.negate()) should be zero.
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        // solium-disable-next-line
        uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }

    // Return the sum of two points of G1
    function add(G1Point memory p1, G1Point memory p2)
        internal
        returns (G1Point memory r) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            // Call bn256Add([p1.X, p1.Y, p2.X, p2.Y])
            success := call(sub(gas, 2000), 6, 0, input, 0x80, r, 0x40)
            // Use "invalid" to make gas estimation work
            //switch success case 0 { invalid }
        }
        require(
            success,
            "Call to the bn256Add precompiled failed (probably an out of gas error?)"
        );
    }

    // Return the product of a point on G1 and a scalar, i.e.
    // p == p.mul(1) and p.add(p) == p.mul(2) for all points p.
    function mul(G1Point memory p, uint256 s)
        internal
        returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            // Call bn256ScalarMul([p.X, p.Y, s])
            success := call(sub(gas, 2000), 7, 0, input, 0x60, r, 0x40)
            // Use "invalid" to make gas estimation work
            //switch success case 0 { invalid }
        }
        require (
            success,
            "Call to bn256ScalarMul failed (probably an out of gas error?)"
        );
    }

    // Return the result of computing the pairing check
    function pairing(G1Point[] memory p1, G2Point[] memory p2)
        internal
        returns (bool) {
        require(
            p1.length == p2.length,
            "Mismatch between the number of elements in G1 and elements in G2"
        );
        // For each pairing check we have 2 coordinates for the elements in G1,
        // and 4 coordinates for the elements in G2
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; i++)
        {
            // Curve point (G1) - 2 coordinates of 32bytes (0x20 in hex)
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            // Twist point (G2) - 2*2 coordinates of 32bytes (0x20 in hex)
            input[i * 6 + 2] = p2[i].X0;
            input[i * 6 + 3] = p2[i].X1;
            input[i * 6 + 4] = p2[i].Y0;
            input[i * 6 + 5] = p2[i].Y1;
        }
        uint256[1] memory out;
        bool success;
        assembly {
            // bn256Pairing precompiled:
            //   https://github.com/ethereum/go-ethereum/blob/master/core/vm/contracts.go#L59
            //
            // The bn256Pairing precompiled takes an input of size N * 192 (a
            // set of pairs of elements (g1, g2) \in G1 x G2 has a size of
            // 192bytes), and carries out a pairing check (not a pairing!)  (ie:
            // the result is a boolean, not an element in G_T).
            //
            // As a consequence, and looking in the Cloudflare bn256 library
            // used in Geth, we see that the PairingCheck function runs a Miller
            // loop on every given pair of elements (g1, g2) \in G1 x G2,
            // multiplies the result of the miller loops and runs
            // finalExponentiation to get a result is G_T. If the result
            // obtained is ONE then the result of the pairing check is True,
            // else False.
            //
            // Looking at the comments above, we see we can run PairingChecks on
            // any number of pairs (g1, g2) \in G1 x G2.  To check something in
            // the form: e(g1, g2) = e(g'1, g'2), we need to call the
            // precompiled bn256Pairing on input [(g1, g2), (neg(g'1), g'2)]
            success := call(sub(gas, 2000), 8, 0, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            //switch success case 0 { invalid }
        }
        require(
            success,
            "Call to the bn256Pairing precompiled failed (probably an out of gas error?)"
        );

        return out[0] != 0;
    }

    // Convenience method for a pairing check for two pairs.
    function pairingProd2(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2)
        internal
        returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }

    // Convenience method for a pairing check for three pairs.
    function pairingProd3(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2)
        internal
        returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }

    // Convenience method for a pairing check for 4 pairs.
    function pairingProd4(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2)
        internal
        returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}
