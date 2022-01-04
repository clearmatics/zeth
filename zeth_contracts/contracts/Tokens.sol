// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

/// Declare the IERC20 interface in order to handle ERC20 tokens transfers to
/// and from the Mixer. Note that we only declare the functions we are
/// interested in, namely, transferFrom() (used to do a Deposit), and
/// transfer() (used to do a withdrawal)
interface IERC20
{
    function transferFrom(address from, address to, uint256 value)
        external
        returns (bool);

    function transfer(address to, uint256 value)
        external
        returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value);
}

/// ERC223 token compatible contract
contract ERC223ReceivingContract
{
    // See:
    // solhint-disable-next-line max-line-length
    //   https://github.com/Dexaran/ERC223-token-standard/blob/Recommended/Receiver_Interface.sol
    struct Token {
        address sender;
        uint256 value;
        bytes data;
        bytes4 sig;
    }

    function tokenFallback(
        address from,
        uint256 value,
        bytes memory data
    )
        public
        pure
    {
        Token memory tkn;
        tkn.sender = from;
        tkn.value = value;
        tkn.data = data;

        // See:
        // solhint-disable-next-line max-line-length
        //   https://solidity.readthedocs.io/en/v0.5.5/types.html#conversions-between-elementary-types
        uint32 u =
            uint32(bytes4(data[0])) +
            uint32(bytes4(data[1]) >> 8) +
            uint32(bytes4(data[2]) >> 16) +
            uint32(bytes4(data[3]) >> 24);
        tkn.sig = bytes4(u);
    }
}
