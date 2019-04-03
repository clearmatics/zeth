pragma solidity ^0.5.0;

import "./MerkleTreeSha256.sol";
import "./Bytes.sol";

/*
 * Declare the ERC20 interface in order to handle ERC20 tokens transfers
 * to and from the Mixer. Note that we only declare the functions we are interested in,
 * namely, transferFrom() (used to do a Deposit), and transfer() (used to do a withdrawal)
**/
contract ERC20 {
    function transferFrom(address from, address to, uint256 value) public;
    function transfer(address to, uint256 value) public;
}

/*
 * ERC223 token compatible contract
**/
contract ERC223ReceivingContract {
    // See: https://github.com/Dexaran/ERC223-token-standard/blob/Recommended/Receiver_Interface.sol
    struct Token {
        address sender;
        uint value;
        bytes data;
        bytes4 sig;
    }

    function tokenFallback(address from, uint value, bytes memory data) public pure {
        Token memory tkn;
        tkn.sender = from;
        tkn.value = value;
        tkn.data = data;

         // see https://solidity.readthedocs.io/en/v0.5.5/types.html#conversions-between-elementary-types
        uint32 u = uint32(bytes4(data[0])) + uint32(bytes4(data[1]) >> 8) + uint32(bytes4(data[2]) >> 16) + uint32(bytes4(data[3]) >> 24);
        tkn.sig = bytes4(u);
    }
}

/*
 * Note1:
 * We might want to use the `Szabo` as a unit for the payments.
 * In fact, as we are using hex strings of length 64bits in the prover to handle the values,
 * the max value we can encode is: "0xFFFFFFFFFFFFFFFF" which corresponds to:
 * "18446744073709551615". If we use this number as WEI, this represents:
 * "18.446744073709551615" ETH. Here we clearly see that we do not as many digits after the
 * floating point, and moreover, we would like to be able to do payments of more than
 * 18ETH. If we use the number "18446744073709551615" (our max) as Szabo, we can make payments
 * up to "18446744073709.551615" ETH which presents a sufficiently high upper bound and which contains
 * 6 digits after the floating point.
 * Here we assume that this is sufficient for our use cases.
 *
 * It is possible to adjust by changing the way the max number "18446744073709551615" is interpreted
 * (changing the unit)
 * See: https://solidity.readthedocs.io/en/v0.4.21/units-and-global-variables.html#ether-units
**/

/*
 * Note2: Because we emit the ciphertexts and the addresses of insertion of the commitments in the tree in the same
 * tx, we have a great way for the recipient to accelerate the verification of a payment.
 * In fact:
 * If Alice receives a payment, then she has the decryption key to retrieve the plaintext of an encrypted note that is emitted in the
 * call of the `transfer`. However, in the same smart contract call are emitted the addresses of insertion of the commitments
 * in the merkle tree. This means that the recipient does not need to verify that the re-computed commitment is "somewhere" in the set of the merkle tree leaves.
 * Instead the recipient JUST has to verify that the recomputed commitment is one of the commitment in the address set that is emitted during the smart contract call.
 * This makes it easier to check the validity of a payment, and is much faster to verify as we directly tell the recipient "where to look for his commitment in the tree".
 * By leveraging this data, we avoid a lot of unecessary overhead just to confirm a payment here.
**/

contract Mixer is MerkleTreeSha256, ERC223ReceivingContract {
    using Bytes for *;

    // The roots of the different updated trees
    mapping(bytes32 => bool) roots;

    // The public list of nullifiers (prevents double spend)
    mapping(bytes32 => bool) nullifiers;

    // JoinSplit description, gives upper bound on number of inputs(nullifiers) and outputs(commitments/ciphertexts) to receive and process
    // IMPORTANT NOTE: We need to employ the same JS configuration than the one used in the cpp prover
    // 2-2 JoinSplit (used as a upper bound in the array of ciphertexts) -- Need to match with the JSDesc used in the circuit
    uint constant jsIn = 2;
    // 2-2 JoinSplit (used as a upper bound in the array of ciphertexts) -- Need to match with the JSDesc used in the circuit
    uint constant jsOut = 2;
    // We have 2 field elements for each digest (root, nullifiers, commitments) and 1 + 1 public values
    uint constant nbInputs = 2 * (1 + jsIn + jsOut) + 1 + 1;
    // Contract variable that indicates the address of the token contract. If token = address(0) then the mixer works with ether.
    address public token;

    // Event to emit the address of a commitment in the merke tree
    event LogAddress(uint commAddr);

    // Event to emit the merkle root of a tree
    event LogMerkleRoot(bytes32 root);

    // Event to emit the ciphertexts of the coins' data to be sent to the recipient of the payment
    // This event is key to obfuscate the tranaction graph while enabling on-chain storage of the coins' data
    // (useful to ease backup of user's wallets)
    event LogSecretCiphers(string ciphertext);

    // Debug only
    event LogDebug(string message);

    // Constructor
    constructor(uint depth, address _token) MerkleTreeSha256(depth) public {
        
        // We log the first root to get started
        bytes32 initialRoot = getRoot();
        roots[initialRoot] = true;
        emit LogMerkleRoot(initialRoot);

        token = _token;
    }
}
