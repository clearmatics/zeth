// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/mpc/groth16/phase2.hpp"

namespace libzeth
{

// Specialization of write_compressed, for the case where ppT == alt_bn128_pp.
// Cannot be a generic template as it relies on calls that are specific to the
// alt_bn128_pp types.
template<>
void srs_mpc_phase2_accumulator<libff::alt_bn128_pp>::write_compressed(
    std::ostream &out) const
{
    using G1 = libff::alt_bn128_G1;
    check_well_formed(*this, "mpc_layer2 (write)");

    // Write cs_hash and sizes first.

    const size_t h_size = H_g1.size();
    const size_t l_size = L_g1.size();
    out.write((const char *)cs_hash, sizeof(mpc_hash_t));
    out.write((const char *)&h_size, sizeof(h_size));
    out.write((const char *)&l_size, sizeof(l_size));

    libff::alt_bn128_G1_write_compressed(out, delta_g1);
    libff::alt_bn128_G2_write_compressed(out, delta_g2);
    for (const G1 &h : H_g1) {
        libff::alt_bn128_G1_write_compressed(out, h);
    }
    for (const G1 &l : L_g1) {
        libff::alt_bn128_G1_write_compressed(out, l);
    }
}

// Specialization of read_compressed, for the case where ppT == alt_bn128_pp.
// Cannot be a generic template as it relies on calls that are specific to the
// alt_bn128_pp types.
template<>
srs_mpc_phase2_accumulator<libff::alt_bn128_pp> srs_mpc_phase2_accumulator<
    libff::alt_bn128_pp>::read_compressed(std::istream &in)
{
    using G1 = libff::alt_bn128_G1;
    using G2 = libff::alt_bn128_G2;

    mpc_hash_t cs_hash;
    size_t h_size;
    size_t l_size;
    in.read((char *)cs_hash, sizeof(mpc_hash_t));
    in.read((char *)&h_size, sizeof(h_size));
    in.read((char *)&l_size, sizeof(l_size));

    G1 delta_g1;
    libff::alt_bn128_G1_read_compressed(in, delta_g1);
    G2 delta_g2;
    libff::alt_bn128_G2_read_compressed(in, delta_g2);

    libff::G1_vector<libff::alt_bn128_pp> h_g1(h_size);
    for (G1 &h : h_g1) {
        libff::alt_bn128_G1_read_compressed(in, h);
    }

    libff::G1_vector<libff::alt_bn128_pp> l_g1(l_size);
    for (G1 &l : l_g1) {
        libff::alt_bn128_G1_read_compressed(in, l);
    }

    srs_mpc_phase2_accumulator<libff::alt_bn128_pp> l2(
        cs_hash, delta_g1, delta_g2, std::move(h_g1), std::move(l_g1));
    check_well_formed(l2, "mpc_layer2 (read)");
    return l2;
}

} // namespace libzeth
