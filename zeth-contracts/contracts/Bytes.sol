pragma solidity ^0.5.0;

library Bytes {
    // Function used to recombine a hash digest split in a uint and a bytes1 together.
    // This is due to the fact we encoded hash digests on field elements of smaller size
    // and thus had to use two field elements to represent them.
    function sha256_digest_from_field_elements(uint input, bytes1 bits) internal pure returns (bytes32) {
        // BECAUSE we know that `input` has only 253 bits from the digest we know that its last 3 bits are going to be zeroes
        // (we want to represent a 253-bit encoded element as a 256-bit digest)
        // BECAUSE we know that `bits` has only 3 bits from the digest we know that its last 5 bits are going to be zeroes
        // (we want to represent a 3-bit encoded element as a 8-bit array)
        // Our goal is to recombine the last (256-253) meaningful bits of input with the 3 meaningful bit of bits
        // NB. the formatting changed the endianness of the variables so we have to fix it when recombining them together/

        // After fixing the endianess of `input`, the byte comprising the (256-253) meaningful bits and padding is the last one
        bytes32 inverted_input1 = flip_endianness_bytes32(bytes32(input));
        bytes1 last_byte_prefix = get_last_byte(inverted_input1);

        // We similarly inverse `bits` and we shift 5 times because we have something like:
        // 0x4 initally, which is in reality 0x04 --> 0000 0100 (in binary).
        // Only the last `100` bits represent meaningful data
        // (the first 5 bit of value '0' are just here to fill the space in the byte).
        // So when we reverse the byte, we have: 0000 0100 --> 0010 0000
        // But again only 3 bits are meaningful in this case. This time the 5 last bits are padding.
        // Thus we push the meaningful data to the right. Now we have something like: `0000 0001`.
        // Note, we store the result of 2 ** n in uint8. However, if n is to big (ie: n > 8).
        // This can overflow. Here this is fine as n is NOT a user input, and does not aim to be changed.
        // Nevertheless we need to keep this in mind. As a consequence we add the "dummy" require below that
        // should fail if we manually change the value of n to be > 8.
        uint8 aInt = uint8(bits);
        uint8 reversed = uint8(reverse_byte(aInt));
        uint8 n = 5;
        require(
            n < 8,
            "The number of right shifts should be inferior to 8"
        );
        uint8 shifted = reversed / 2 ** n;
        bytes1 shifted_byte = bytes1(shifted);

        // We know that the last 3 bits of `input` are '0' bits that have been padded to create a byte32 out of a 253 bit string
        // Thus now, we have the last byte of `input` being something like XXXX X000 (where X represent meangful bits)
        // And `reversed` (the only meaningful byte of this input) being in the form: 0000 0YYY (where Y represent
        // meaningful data). The only thing we need to do to recompose the digest our of our 2 field elements, is to XOR
        // the last bytes of each reverse input.
        bytes1 res = last_byte_prefix ^ shifted_byte;

        // We now recombine the first 31 bytes of the flipped `input` with the recombine byte `res`
        bytes memory bytes_digest = new bytes(32);
        for (uint i = 0; i < 31; i++) {
            bytes_digest[i] = inverted_input1[i];
        }

        bytes_digest[31] = res;
        bytes32 sha256_digest = bytes_to_bytes32(bytes_digest, 0);

        return (sha256_digest);
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
        return (( c >> ((a & 0xF)*8)) & 0xF0) +
            (( c >> (((a >> 4)&0xF)*8) + 4) & 0xF);
    }

    function swap_bit_order(bytes32 input) internal pure returns (bytes32) {
        bytes32 rev;
        for (uint i = 0 ; i < 256 ; i++){
            rev = rev << 1;
            if (uint((input << (255-i)) >> 255) == 1) {
                rev = rev ^ bytes32(0x0000000000000000000000000000000000000000000000000000000000000001);
            }
        }
        return rev;
    }
}
