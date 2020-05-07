# On-chain verification contracts

The Byzantium hard fork of Ethereum has introduced [pre-compiled contracts for elliptic curves operations](https://github.com/ethereum/go-ethereum/blob/master/core/vm/contracts.go#L56-L59).

As we know that a SNARK proof is composed of a few (bilinear) group elements, and that the verification mainly consists
in doing pairing operations to check quadratic equality, one can see that it is now possible to verify SNARK proofs on-chain
(**Assuming that the encoding scheme is compatible with the publicly verifiable setting**, here this is the case because
the SNARK we use, uses exponentiation in a bilinear group as encoding).

This repository contains all the smart-contracts that are used to carry-out the on-chain verification, and to maintain the
merkle tree of commitments as described in the zerocash paper.
