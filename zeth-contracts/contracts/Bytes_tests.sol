// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

import './Bytes.sol';

contract Bytes_tests {
	using Bytes for *;

	constructor() public {
        // Nothing
    }

	function testReverseByte() public pure returns (bool) {
		uint number = 16; // 0001 0000 (binary)
		uint reverse_number = Bytes.reverse_byte(number);

		bool ok = (reverse_number == 8);
		require(
			ok,
			"[testReverseByte] Failed"
		);

		return ok;
	}

	function testGetLastByte() public pure returns (bool) {
		bytes32 test_bytes = 0x00000000000000000000000000000000000000000000000000000000000000AF;
		bytes1 last_byte = Bytes.get_last_byte(test_bytes);

		bool ok = (last_byte == 0xAF);
		require(
			ok,
			"[testGestLastByte] Failed"
		);

		return ok;
	}

    function testFlipEndiannessBytes32() public pure returns (bool) {
		bytes32 test_bytes = 0x00000000000000000000000000000000000000000000000000000000000000AF;
		bytes32 reversed_bytes = Bytes.flip_endianness_bytes32(test_bytes);

		bool ok = (reversed_bytes == 0xF500000000000000000000000000000000000000000000000000000000000000);
		require(
			ok,
			"[testFlipEndianness] Failed"
		);

		return ok;
	}

    function testBytesToBytes32() public pure returns (bool) {
        bytes memory test_bytes = new bytes(32);
        for (uint i; i < 15; i++) {
            test_bytes[i] = bytes1(0xAB);
        }
        for (uint i = 15; i <= 31; i++) {
            test_bytes[i] = bytes1(0xCD);
        }
        bytes32 test_bytes32 = Bytes.bytes_to_bytes32(test_bytes, 0);

        bool ok = (test_bytes32 == bytes32(0xabababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd));
        require(
            ok,
            "[testBytesToBytes32] Failed"
        );

        return ok;
    }

    function testSha256DigestFromFieldElements() public pure returns (bool) {
        uint256[] memory test_input = new uint[](2);
        test_input[0] = 0x16cc12975b9a52d97c6a5c0cc91b76b7432306724ed800ef1c29e86393b1e757;
        test_input[1] = 0x4;
        bytes32 test_res = Bytes.sha256_digest_from_field_elements(test_input);

        bool ok = (test_res == bytes32(0xeae78dc9c6179438f7001b724e60c4c2ed6ed893303a563e9b4a59dae9483369));
        require(
             ok,
            "[testSha256DigestFromFieldElements] Failed"
        );

        return ok;
    }
}
