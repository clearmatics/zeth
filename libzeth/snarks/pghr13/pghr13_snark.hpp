// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_PGHR13_PGHR13_SNARK_HPP__
#define __ZETH_SNARKS_PGHR13_PGHR13_SNARK_HPP__

#include <boost/filesystem.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

namespace libzeth
{

template<typename ppT> class pghr13_snark
{
public:
    typedef libsnark::r1cs_ppzksnark_proving_key<ppT> ProvingKeyT;
    typedef libsnark::r1cs_ppzksnark_verification_key<ppT> VerifKeyT;
    typedef libsnark::r1cs_ppzksnark_keypair<ppT> KeypairT;
    typedef libsnark::r1cs_ppzksnark_proof<ppT> ProofT;

    /// Run the trusted setup and return the keypair for the circuit
    static KeypairT generate_setup(
        const libsnark::protoboard<libff::Fr<ppT>> &pb);

    /// Generate the proof
    static ProofT generate_proof(
        const libsnark::protoboard<libff::Fr<ppT>> &pb,
        const ProvingKeyT &proving_key);

    /// Verify proof
    static bool verify(
        const libsnark::r1cs_primary_input<libff::Fr<ppT>> &primary_inputs,
        const ProofT &proof,
        const VerifKeyT &verification_key);

    /// Write verification as json
    static std::ostream &verification_key_write_json(
        const VerifKeyT &, std::ostream &);

    /// Write verification key as bytes
    static std::ostream &verification_key_write_bytes(
        const VerifKeyT &, std::ostream &);

    /// Read a verification key as bytes
    static VerifKeyT verification_key_read_bytes(std::istream &);

    /// Write proving key as bytes
    static std::ostream &proving_key_write_bytes(
        const ProvingKeyT &, std::ostream &);

    /// Read proving key as bytes
    static ProvingKeyT proving_key_read_bytes(std::istream &);

    /// Write proof as json
    static std::ostream &proof_write_json(const ProofT &, std::ostream &);

    /// Write a keypair to a stream.
    static std::ostream &keypair_write_bytes(const KeypairT &, std::ostream &);

    /// Read a keypair from a stream.
    static KeypairT keypair_read_bytes(std::istream &);
};

} // namespace libzeth

#include "libzeth/snarks/pghr13/pghr13_snark.tcc"

#endif // __ZETH_SNARKS_PGHR13_PGHR13_SNARK_HPP__
