import './Bytes.sol';

contract Bytes_tests {
	using Bytes for *;

	constructor() public {
        // Nothing
    }

	function testReverseByte() public returns (bool) {
		uint number = 16; // 0001 0000 (binary)
		uint reverse_number = reverseByte(16);

		bool ok = (reverse_number == 8);
		require(
			ok,
			"[testReverseByte] Failed"
		);

		return ok;
	}

	function testGetLastByte() public returns (bool) {
		bytes32 test_bytes = 0x00000000000000000000000000000000000000000000000000000000000000AF;
		bytes1 last_byte = getLastByte(test_bytes);

		bool ok = (last_byte == 0xAF);
		require(
			ok,
			"[testGestLastByte] Failed"
		);

		return ok;
	}

    function testFlipEndianness() public returns (bool) {
		bytes32 test_bytes = 0x00000000000000000000000000000000000000000000000000000000000000AF;
		bytes32 reversed_bytes = flip_endianness(test_bytes);

		bool ok = (reversed_bytes == 0xF500000000000000000000000000000000000000000000000000000000000000);
		require(
			ok,
			"[testFlipEndianness] Failed"
		);

		return ok;
	}

	function testBytesToBytes32() public returns (bool) {
		 memory test_bytes = new bytes(32);
        for (uint i = 0; i < 15; i++) {
            test_bytes[i] = bytes1(0xAB);
        }
        for (uint i = 15; i <= 31; i++) {
            test_bytes[i] = bytes1(0xCD);
        }
        bytes32 test_bytes32 = bytesToBytes32(test_bytes, 0);

		bool ok = (test_bytes32 == bytes32(0xabababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd));
		require(
			ok,
			"[testBytesToBytes32] Failed"
		);

		return ok;
	}
}
