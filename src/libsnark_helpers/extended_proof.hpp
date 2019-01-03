#ifndef __ZETH_EXTENDED_PROOF_HPP__
#define __ZETH_EXTENDED_PROOF_HPP__

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include "libsnark_helpers/libsnark_helpers.hpp"

/*
 * An extended_proof is a data structure containing a proof and the corresponding primary inputs
 * It corresponds to the data needed for the verifier to be able to run the verifying
 * algorithm.
 **/
template<typename ppT>
class extended_proof {
private:
    std::shared_ptr<libsnark::r1cs_ppzksnark_proof<ppT>> proof;
    std::shared_ptr<libsnark::r1cs_ppzksnark_primary_input<ppT>> primary_inputs;

public:
    extended_proof(libsnark::r1cs_ppzksnark_proof<ppT> &in_proof,
                    libsnark::r1cs_ppzksnark_primary_input<ppT> &in_primary_input);

    libsnark::r1cs_ppzksnark_proof<ppT> get_proof();
    libsnark::r1cs_ppzksnark_primary_input<ppT> get_primary_input();

	// Write on disk
	void write_extended_proof(boost::filesystem::path path = "");
	void write_proof(boost::filesystem::path path = "");
	void write_primary_input(boost::filesystem::path path = "");

    // Display on stdout
    void dump_proof();
    void dump_primary_inputs();
};

#include "extended_proof.tcc"

#endif
