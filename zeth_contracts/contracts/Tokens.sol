// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

// Declare the ERC20 interface in order to handle ERC20 tokens transfers to and
// from the Mixer. Note that we only declare the functions we are interested in,
// namely, transferFrom() (used to do a Deposit), and transfer() (used to do a
// withdrawal)
contract ERC20 {
    function transferFrom(address from, address to, uint256 value) public;
    function transfer(address to, uint256 value) public;
}

// ERC223 token compatible contract
contract ERC223ReceivingContract {
    // See:
    //   https://github.com/Dexaran/ERC223-token-standard/blob/Recommended/Receiver_Interface.sol
    struct Token {
        address sender;
        uint256 value;
        bytes data;
        bytes4 sig;
    }

    function tokenFallback(address from, uint256 value, bytes memory data)
        public pure {
        Token memory tkn;
        tkn.sender = from;
        tkn.value = value;
        tkn.data = data;

         // See:
         //   https://solidity.readthedocs.io/en/v0.5.5/types.html#conversions-between-elementary-types
        uint32 u =
            uint32(bytes4(data[0])) +
            uint32(bytes4(data[1]) >> 8) +
            uint32(bytes4(data[2]) >> 16) +
            uint32(bytes4(data[3]) >> 24);
        tkn.sig = bytes4(u);
    }
}
