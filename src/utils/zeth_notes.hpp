#ifndef __ZETH_NOTE_HPP__
#define __ZETH_NOTE_HPP__

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include "libsnark_helpers/libsnark_helpers.hpp"

/*
 * A zeth note is a data structure that contains:
 *  - addr_pk
 *  - v
 *  - rho
 *  - trap_r
 *  - trap_s
 *  - cm
 **/
template<typename ppT>
class zeth_note {
private:
    std::shared_ptr<libsnark::r1cs_ppzksnark_proof<ppT>> proof;
    std::shared_ptr<libsnark::r1cs_ppzksnark_primary_input<ppT>> primary_inputs;

public:
    zeth_note(addr_pk, v, rho, trap_r, trap_s, cm);

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
