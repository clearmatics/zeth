// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

library Bytes {
    // Function used to recombine a hash digest split in a uint and a bytes1 together.
    // This is due to the fact we encoded hash digests on field elements of smaller size
    // and thus had to use two field elements to represent them.
    function sha256_digest_from_field_elements(uint input, bytes1 bits) internal pure returns (bytes32) {
        // BECAUSE we know that `input` has only 253 bits from the digest we know that its last 3 bits are going to be zeroes
        // (we want to represent a 253-bit encoded element as a 256-bit digest)
        // BECAUSE we know that `bits` has only 3 bits from the digest we know that its first 5 bits are going to be zeroes
        // (we want to represent a 3-bit encoded element as a 8-bit array)
        // Our goal is to recombine the last (256-253) meaningful bits of input with the 3 meaningful bit of bits

        bytes32 input_bytes = bytes32(input);

        // If `bits` is 0, we do not need to recombine (the input's padding is equal to the value to recombine).
        if (uint8(bits) == 0) {
            return input_bytes;
        }
        // Else, we continue
        bytes1 last_byte_prefix = get_last_byte(input_bytes);

        // We know that the last 3 bits of `input` are '0' bits that have been padded to create a byte32 out of a 253 bit string
        // Thus now, we have the last byte of `input` being something like XXXX X000 (where X represent meangful bits)
        // And `bits` being in the form: 0000 0YYY (where Y represent meaningful data).
        // The only thing we need to do to recompose the digest of 2 field elements, is to XOR the last bytes of each reverse input.
        bytes1 res = last_byte_prefix ^ bits;

        // We now recombine the first 31 bytes of the flipped `input` with the recombine byte `res`
        bytes memory bytes_digest = new bytes(32);
        for (uint i = 0; i < 31; i++) {
            bytes_digest[i] = input_bytes[i];
        }
        bytes_digest[31] = res;
        bytes32 sha256_digest = bytes_to_bytes32(bytes_digest, 0);

        return sha256_digest;
    }

    function bytes_to_bytes32(bytes memory b, uint offset) internal pure returns (bytes32) {
        bytes32 out;

        for (uint i = 0; i < 32; i++) {
            out |= bytes32(b[offset + i] & 0xFF) >> (i * 8);
        }
        return out;
    }

    function flip_endianness_bytes32(bytes32 a) internal pure returns(bytes32) {
        uint r;
        uint b;
        for (uint i = 0; i < 32; i++) {
            b = (uint(a) >> ((31-i)*8)) & 0xff;
            b = reverse_byte(b);
            r += b << (i*8);
        }
        return bytes32(r);
    }

    function int256ToBytes8(uint256 input) internal pure returns (bytes8) {
        bytes memory inBytes = new bytes(32);
        assembly {
            mstore(add(inBytes, 32), input)
        }

        bytes memory subBytes = subBytes(inBytes, 24, 32);
        bytes8 resBytes8;
        assembly {
            resBytes8 := mload(add(subBytes, 32))
        }

        return resBytes8;
    }

    function subBytes(bytes memory inBytes, uint startIndex, uint endIndex) internal pure returns (bytes memory) {
        bytes memory result = new bytes(endIndex-startIndex);
        for(uint i = startIndex; i < endIndex; i++) {
            result[i-startIndex] = inBytes[i];
        }
        return result;
    }

    // Function used to get the decimal value of the public values on both side of the joinsplit
    // (given as primary input) from the hexadecimal primary values
    function get_value_from_inputs(bytes8 valueBytes) internal pure returns(uint64) {
        bytes8 flippedBytes = flip_endianness_bytes8(valueBytes);
        uint64 value = get_int64_from_bytes8(flippedBytes);
        return value;
    }

    function flip_endianness_bytes8(bytes8 a) internal pure returns(bytes8) {
        uint64 r;
        uint64 b;
        for (uint i = 0; i < 8; i++) {
            b = (uint64(a) >> ((7-i)*8)) & 0xff;
            b = reverse_bytes8(b);
            r += b << (i*8);
        }
        return bytes8(r);
    }

    function reverse_bytes8(uint a) internal pure returns (uint8) {
        return uint8(reverse_byte(a));
    }

    function get_int64_from_bytes8(bytes8 input) internal pure returns(uint64) {
        return uint64(input);
    }

    function get_last_byte(bytes32 x) internal pure returns(bytes1) {
        return x[31];
    }

    // Reverses the bit endianness of the byte
    // Example:
    // Input: 8 (decimal) -> 0000 1000 (binary)
    // Output: 0001 0000 (binary) -> 16 (decimal)
    function reverse_byte(uint a) internal pure returns (uint) {
        uint c = 0xf070b030d0509010e060a020c0408000;

        return (( c >> ((a & 0xF)*8)) & 0xF0)   +
            (( c >> (((a >> 4)&0xF)*8) + 4) & 0xF);
    }

}
