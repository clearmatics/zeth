// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./Tokens.sol";
import "./OTSchnorrVerifier.sol";
import "./BaseMerkleTree.sol";

/// MixerBase implements the functions shared across all Mixers (regardless
/// which zkSNARK is used)
abstract contract MixerBase is BaseMerkleTree, ERC223ReceivingContract
{
    // The roots of the different updated trees
    mapping(bytes32 => bool) private _roots;

    // The public list of nullifiers (prevents double spend)
    mapping(bytes32 => bool) private _nullifiers;

    // Structure of the verification key and proofs is opaque, determined by
    // zk-snark verification library.
    uint256[] internal _vk;

    // Contract variable that indicates the address of the token contract
    // If token = address(0) then the mixer works with ether
    address private _token;

    // Contract that is allowed to call the `dispatch` method, passing in the
    // correct _vk_hash. (Disable the dispatch method by setting
    // _permitted_dispatcher = 0, in which case _vk_hash is unused.)
    address private _permitted_dispatcher;

    // The acceptable value of _vk_hash, passed in by a trusted dispatcher.
    uint256[2] private _vk_hash;

    // JoinSplit description, gives the number of inputs (nullifiers) and
    // outputs (commitments/ciphertexts) to receive and process.
    //
    // IMPORTANT NOTE: We need to employ the same JS configuration than the one
    // used in the cpp prover. Here we use 2 inputs and 2 outputs (it is a 2-2
    // JS).
    uint256 internal constant JSIN = 2; // Number of nullifiers
    uint256 internal constant JSOUT = 2; // Number of commitments/ciphertexts

    // Size of the public values in bits
    uint256 internal constant PUBLIC_VALUE_BITS = 64;

    // Public values mask
    uint256 internal constant PUBLIC_VALUE_MASK = (1 << PUBLIC_VALUE_BITS) - 1;

    // Total number of bits for public values. Digest residual bits appear
    // after these.
    uint256 internal constant TOTAL_PUBLIC_VALUE_BITS = 2 * PUBLIC_VALUE_BITS;

    uint256 internal constant DIGEST_LENGTH = 256;

    // Number of hash digests in the primary inputs:
    //   1 (the root)
    //   2 * JSIN (nullifier and message auth tag per JS input)
    //   JSOUT (commitment per JS output)
    uint256 internal constant NUM_HASH_DIGESTS = 1 + 2 * JSIN;

    // All code assumes that public values and residual bits can be encoded in
    // a single field element.
    uint256 internal constant NUM_FIELD_RESIDUAL = 1;

    // The number of public inputs are:
    // - 1 (the root)
    // - JSIN (the nullifiers)
    // - JSOUT (the commitments)
    // - 1 (hsig)
    // - JsIn (the message auth. tags)
    // - NUM_FIELD_RESIDUAL (the residual bits not fitting in a single field
    //   element and the in and out public values)
    uint256 internal constant NUM_INPUTS =
        1 + JSOUT + NUM_HASH_DIGESTS + NUM_FIELD_RESIDUAL;

    // The unit used for public values (ether in and out), in Wei. Must match
    // the python wrappers. Use Szabos (10^12 Wei).
    uint64 internal constant PUBLIC_UNIT_VALUE_WEI = 1e12;

    event LogMix(
        bytes32 root,
        bytes32[JSIN] nullifiers,
        bytes32[JSOUT] commitments,
        bytes[JSOUT] ciphertexts
    );

    /// Debug only
    event LogDebug(string message, uint256 value);

    /// Constructor
    constructor(
        uint256 depth,
        address token_address,
        uint256[] memory vk,
        address permitted_dispatcher,
        uint256[2] memory vk_hash
    )
        BaseMerkleTree(depth)
    {
        bytes32 initialRoot = nodes[0];
        _roots[initialRoot] = true;
        _vk = vk;
        _token = token_address;
        _permitted_dispatcher = permitted_dispatcher;
        _vk_hash = vk_hash;
    }

    /// Function allowing external users of the contract to retrieve some of
    /// the constants used in the mixer (since the solidity interfaces do not
    /// export this information as-of the current version). The intention is
    /// that external users and contraacts can query this function and ensure
    /// that they are compatible with the mixer configurations.
    ///
    /// Returns the number of input notes, the number of output notes and the
    /// total number of primary inputs.
    function get_constants()
        external
        pure
        returns (
            uint256 js_in_out,
            uint256 js_out_out,
            uint256 num_inputs_out
        )
    {
        js_in_out = JSIN;
        js_out_out = JSOUT;
        num_inputs_out = NUM_INPUTS;
    }

    /// Permitted dispatchers may call this entry point if they have verified
    /// the associated proof. This is technically part of the
    /// IZecaleApplication interface, see
    /// https://github.com/clearmatics/zecale
    function dispatch(
        uint256[2] memory nested_vk_hash,
        uint256[] memory nested_inputs,
        bytes memory nested_parameters
    )
        public
        payable
    {
        // Sanity / permission checkcheck
        require(
            msg.sender == _permitted_dispatcher, "dispatcher not permitted");
        require(
            nested_vk_hash[0] == _vk_hash[0] &&
            nested_vk_hash[1] == _vk_hash[1],
            "invalid nested_vk_hash");
        require(nested_inputs.length == 1, "invalid num nested inputs");

        // Decode the nested parameters
        // TODO: convert ciphertext array without copying
        (uint256[4] memory vk,
         uint256 sigma,
         uint256[] memory public_data,
         bytes[] memory decoded_ciphertexts) = abi.decode(
             nested_parameters, (uint256[4], uint256, uint256[], bytes[]));
        require(
            public_data.length == NUM_INPUTS,
            "invalid number of public inputs in decoded data.");
        require(
            decoded_ciphertexts.length == JSOUT,
            "invalid number of ciphertexts in decoded data.");

        bytes[JSOUT] memory ciphertexts;
        for (uint256 i = 0 ; i < JSOUT ; ++i) {
            ciphertexts[i] = decoded_ciphertexts[i];
        }

        // Copy the public inputs into a fixed-size array.
        // TODO: convert without copying.
        uint256[NUM_INPUTS] memory inputs;
        for (uint256 i = 0 ; i < NUM_INPUTS ; ++i) {
            inputs[i] = public_data[i];
        }

        // Ensure that the primary input to the zk-proof (validated and passed
        // in by the dispatcher), matches the hash of the public inputs.
        require(
            nested_inputs[0] == hash_public_proof_data(inputs),
            "hash of public data does not match primary input");

        // 1. Check the root and the nullifiers
        bytes32[JSIN] memory nullifiers;
        check_mkroot_nullifiers_hsig_append_nullifiers_state(
            vk, inputs, nullifiers);

        // 2.a Verify the signature on the hash of data_to_be_signed.
        // hash_to_be_signed is expected to have been created without the proof
        // data.
        bytes32 hash_to_be_signed = sha256(
            abi.encodePacked(
                uint256(uint160(msg.sender)),
                ciphertexts[0],
                ciphertexts[1],
                inputs
            )
        );

        require(
            OTSchnorrVerifier.verify(
                vk[0], vk[1], vk[2], vk[3], sigma, hash_to_be_signed),
            "Invalid signature in dispatch"
        );

        mix_append_commitments_emit_and_handle_public_values(
            inputs, ciphertexts, nullifiers);
    }

    /// This function is used to execute payments in zero knowledge.
    /// The format of `proof` is internal to the zk-snark library.
    /// The `inputs` array is the set of scalar inputs to the proof.
    /// We assume that each input occupies a single uint256.
    function mix(
        uint256[] memory proof,
        uint256[4] memory vk,
        uint256 sigma,
        uint256[NUM_INPUTS] memory public_inputs,
        bytes[JSOUT] memory ciphertexts
    )
        public
        payable
    {
        // 1. Check the root and the nullifiers
        bytes32[JSIN] memory nullifiers;
        check_mkroot_nullifiers_hsig_append_nullifiers_state(
            vk, public_inputs, nullifiers);

        // 2.a Verify the signature on the hash of data_to_be_signed
        bytes32 hash_to_be_signed = sha256(
            abi.encodePacked(
                uint256(uint160(msg.sender)),
                // Unfortunately, we have to unroll this for now. We could
                // replace encodePacked with a custom function but this would
                // increase complexity and possibly gas usage.
                ciphertexts[0],
                ciphertexts[1],
                proof,
                public_inputs
            )
        );
        require(
            OTSchnorrVerifier.verify(
                vk[0], vk[1], vk[2], vk[3], sigma, hash_to_be_signed),
            "Invalid signature: Unable to verify the signature correctly"
        );

        // 2.b Verify the proof
        uint256 public_inputs_hash = hash_public_proof_data(public_inputs);
        require(
            verify_zk_proof(proof, public_inputs_hash),
            "Invalid proof: Unable to verify the proof correctly"
        );

        mix_append_commitments_emit_and_handle_public_values(
            public_inputs, ciphertexts, nullifiers);
    }

    function mix_append_commitments_emit_and_handle_public_values(
        uint256[NUM_INPUTS] memory inputs,
        bytes[JSOUT] memory ciphertexts,
        bytes32[JSIN] memory nullifiers
    )
        internal
    {
        // 3. Append the commitments to the tree
        bytes32[JSOUT] memory commitments;
        assemble_commitments_and_append_to_state(inputs, commitments);

        // 4. Add the new root to the list of existing roots
        bytes32 new_merkle_root = recomputeRoot(JSOUT);
        add_merkle_root(new_merkle_root);

        // 5. Emit the all Mix data
        emit LogMix(
            new_merkle_root,
            nullifiers,
            commitments,
            ciphertexts
        );

        // 6. Get the public values in Wei and modify the state depending on
        // their values
        process_public_values(inputs);
    }

    function hash_public_proof_data(uint256[NUM_INPUTS] memory public_data)
        internal
        returns (uint256)
    {
        // Initialize h with the IV and hash each public data value (see
        // client/zeth/core/input_hasher.py for details)
        bytes32 h;
        h = bytes32(uint256(
            // solhint-disable-next-line max-line-length
            13196537064117388418196223856311987714388543839552400408340921397545324034315));
        for (uint256 i = 0 ; i < NUM_INPUTS; ++i) {
            h = hash(h, bytes32(public_data[i]));
        }
        h = hash(h, bytes32(NUM_INPUTS));
        return uint256(h);
    }

    /// This function is used to extract the public values (vpub_in, vpub_out)
    /// from the residual field element(S)
    function assemble_public_values(uint256 residual_bits)
        internal
        pure
        returns (
            uint256 vpub_in,
            uint256 vpub_out
        )
    {
        // vpub_out and vpub_in occupy the first and second PUBLIC_VALUE_BITS
        vpub_out = (residual_bits & PUBLIC_VALUE_MASK) * PUBLIC_UNIT_VALUE_WEI;
        vpub_in = ((residual_bits >> PUBLIC_VALUE_BITS) & PUBLIC_VALUE_MASK)
            * PUBLIC_UNIT_VALUE_WEI;
    }

    /// This function is used to reassemble hsig given the primary_inputs.
    /// To do so, we extract the remaining bits of hsig from the residual field
    /// element(S) and combine them with the hsig field element
    function assemble_hsig(
        uint256[NUM_INPUTS] memory primary_inputs
    )
        internal
        pure
        returns(bytes32 hsig)
    {
        // The h_sig residual bits are after the JSIN authentication tags and
        // JSIN nullifier bits.
        return extract_bytes32(
            primary_inputs[1 + JSIN + JSOUT],
            primary_inputs[1 + JSOUT + NUM_HASH_DIGESTS],
            2 * JSIN
        );
    }

    /// This function is used to reassemble the nullifiers given the nullifier
    /// index [0, JSIN[ and the primary_inputs To do so, we extract the
    /// remaining bits of the nullifier from the residual field element(S) and
    /// combine them with the nullifier field element
    function assemble_nullifier(
        uint256 index,
        uint256[NUM_INPUTS] memory primary_inputs
    )
        internal
        pure
        returns(bytes32 nf)
    {
        // We first check that the nullifier we want to retrieve exists
        require(index < JSIN, "nullifier index overflow");

        // Nullifier residual bits follow the JSIN message authentication tags.
        return extract_bytes32(
            primary_inputs[1 + JSOUT + index],
            primary_inputs[1 + JSOUT + NUM_HASH_DIGESTS],
            JSIN + index
        );
    }

    // ======================================================================
    // Reminder: Remember that the primary inputs are ordered as follows:
    //
    //   [Root, CommitmentS, NullifierS, h_sig, h_iS, Residual Element(s)]
    //
    // ie, below is the index mapping of the primary input elements on the
    // protoboard:
    //
    //   <Merkle Root>               0
    //   <Commitment[0]>             1
    //   ...
    //   <Commitment[JSOUT - 1]>     JSOUT
    //   <Nullifier[0]>              JSOUT + 1
    //   ...
    //   <Nullifier[JSIN]>           JSOUT + JSIN
    //   <h_sig>                     JSOUT + JSIN + 1
    //   <Message Auth Tag[0]>       JSOUT + JSIN + 2
    //   ...
    //   <Message Auth Tag[JSIN]>    JSOUT + 2*JSIN + 1
    //   <Residual Field Elements>   JSOUT + 2*JSIN + 2
    //
    // The Residual field elements are structured as follows:
    //
    //   255                                         128         64           0
    //   |<empty>|<h_sig>|<nullifiers>|<msg_auth_tags>|<v_pub_in>)|<v_pub_out>|
    //
    // where each entry entry after public output and input holds the
    // (curve-specific) number residual bits for the corresponding 256 bit
    // value.
    // ======================================================================
    //
    // Utility function to extract a full uint256 from a field element and the
    // n-th set of residual bits from `residual`. This function is
    // curve-dependent.
    function extract_bytes32(
        uint256 field_element,
        uint256 residual,
        uint256 residual_bits_set_idx
    )
        internal
        pure
        virtual
        returns(bytes32);

    // Implementations must implement the verification algorithm of the
    // selected SNARK.
    function verify_zk_proof(
        uint256[] memory proof,
        uint256 public_inputs_hash
    )
        internal
        virtual
        returns (bool);

    /// This function processes the primary inputs to append and check the root
    /// and nullifiers in the primary inputs (instance) and modifies the state
    /// of the mixer contract accordingly. (ie: Appends the commitments to the
    /// tree, appends the nullifiers to the list and so on).
    function check_mkroot_nullifiers_hsig_append_nullifiers_state(
        uint256[4] memory vk,
        uint256[NUM_INPUTS] memory primary_inputs,
        bytes32[JSIN] memory nfs)
        internal
    {
        // 1. We re-assemble the full root digest and check it is in the tree
        require(
            _roots[bytes32(primary_inputs[0])],
            "Invalid root: This root doesn't exist"
        );

        // 2. We re-assemble the nullifiers (JSInputs) and check they were not
        // already seen.
        for (uint256 i = 0; i < JSIN; i++) {
            bytes32 nullifier = assemble_nullifier(i, primary_inputs);
            require(
                !_nullifiers[nullifier],
                "Invalid nullifier: This nullifier has already been used"
            );
            _nullifiers[nullifier] = true;

            nfs[i] = nullifier;
        }

        // 3. We re-compute h_sig, re-assemble the expected h_sig and check
        // they are equal (i.e. that h_sig re-assembled was correctly generated
        // from vk).
        bytes32 expected_hsig = sha256(abi.encodePacked(nfs, vk));
        bytes32 hsig = assemble_hsig(primary_inputs);
        require(
            expected_hsig == hsig,
            "Invalid hsig: This hsig does not correspond to the hash of vk and"
            " the nfs"
        );
    }

    function assemble_commitments_and_append_to_state(
        uint256[NUM_INPUTS] memory primary_inputs,
        bytes32[JSOUT] memory comms
    )
        internal
    {
        // We re-assemble the commitments (JSOutputs)
        for (uint256 i = 0; i < JSOUT; i++) {
            bytes32 current_commitment = bytes32(primary_inputs[1 + i]);
            comms[i] = current_commitment;
            insert(current_commitment);
        }
    }

    function process_public_values(uint256[NUM_INPUTS] memory primary_inputs)
        internal
    {
        // We get vpub_in and vpub_out in wei
        (uint256 vpub_in, uint256 vpub_out) = assemble_public_values(
            primary_inputs[1 + JSOUT + NUM_HASH_DIGESTS]);

        // If the vpub_in is > 0, we need to make sure the right amount is paid
        if (vpub_in > 0) {
            if (_token != address(0)) {
                IERC20 erc20Token = IERC20(_token);
                erc20Token.transferFrom(msg.sender, address(this), vpub_in);
            } else {
                require(
                    msg.value == vpub_in,
                    "Wrong msg.value: Value paid is not correct"
                );
            }
        } else {
            // If vpub_in = 0, return incoming Ether to the caller
            if (msg.value > 0) {
                // solhint-disable-next-line
                (bool success, ) = msg.sender.call{value: msg.value}("");
                require(success, "vpub_in return transfer failed");
            }
        }

        // If value_pub_out > 0 then we do a withdraw.  We retrieve the
        // msg.sender and send him the appropriate value IF proof is valid
        if (vpub_out > 0) {
            if (_token != address(0)) {
                IERC20 erc20Token = IERC20(_token);
                erc20Token.transfer(msg.sender, vpub_out);
            } else {
                // solhint-disable-next-line
                (bool success, ) = msg.sender.call{value: vpub_out}("");
                require(success, "vpub_out transfer failed");
            }
        }
    }

    function add_merkle_root(bytes32 root) internal
    {
        _roots[root] = true;
    }
}
