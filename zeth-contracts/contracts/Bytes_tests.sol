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
        uint test_input0 = 0x16cc12975b9a52d97c6a5c0cc91b76b7432306724ed800ef1c29e86393b1e757;
        bytes1 test_input1 = bytes1(uint8(0x4));
        bytes32 test_res = Bytes.sha256_digest_from_field_elements(test_input0 << 3, test_input1);

        bool ok = (test_res == bytes32(0xb66094badcd296cbe352e06648dbb5ba1918339276c00778e14f431c9d8f3abc));
        require(
             ok,
            "[testSha256DigestFromFieldElements] Failed"
        );

        return ok;
    }
}
