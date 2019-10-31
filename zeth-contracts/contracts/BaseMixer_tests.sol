pragma solidity ^0.5.0;

import './BaseMixer.sol';

contract BaseMixer_tests {
    using Bytes for *;
    BaseMixer bm = new BaseMixer(
        3,
        0x0000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000);

    function test_extract_extra_bits() public view returns (bool) {
        // The variable `test_bytes` represent a dummy primary input array
        uint[] memory test_bytes = new uint[](9);
        test_bytes[0] = 0; // merkle root
        test_bytes[1] = 1; // sn 0
        test_bytes[2] = 1; // sn 1
        test_bytes[3] = 2; // cm 0
        test_bytes[4] = 2; // cm 1
        test_bytes[5] = 3; // h sig
        test_bytes[6] = 4; // h 0
        test_bytes[7] = 4; // h 1
        // residual bits = v_in || v_out || h_sig || {sn} || {cm} || {h}
        // v_in  = 0xFFFFFFFFFFFFFFFF
        // v_out = 0x0000000000000000
        // h_sig = 111
        // sn0   = 000
        // sn1   = 001
        // cm0   = 010
        // cm1   = 011
        // h0    = 100
        // h1    = 101
        test_bytes[8] = 713623846352979940490457358497079434602616037; // residual bits
        bool ok = true;
        bytes1 res;
        uint start;
        uint end = 2;

        for (uint i; i<6; i++) {
            res = bm.extract_extra_bits(start, end, test_bytes);
            ok = ( uint(uint8(res)) == i );
            start += 3;
            end += 3;
        }
        require(
            ok,
            "[test_extract_extra_bits] Failed"
        );
        
        return ok;
    }
}