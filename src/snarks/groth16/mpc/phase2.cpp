#include "snarks/groth16/mpc/phase2.hpp"

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

    const size_t H_size = H_g1.size();
    const size_t L_size = L_g1.size();
    out.write((const char *)cs_hash, sizeof(srs_mpc_hash_t));
    out.write((const char *)&H_size, sizeof(H_size));
    out.write((const char *)&L_size, sizeof(L_size));

    libff::alt_bn128_G1_write_compressed(out, delta_g1);
    libff::alt_bn128_G2_write_compressed(out, delta_g2);
    for (const G1 h : H_g1) {
        libff::alt_bn128_G1_write_compressed(out, h);
    }
    for (const G1 l : L_g1) {
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

    srs_mpc_hash_t cs_hash;
    size_t H_size;
    size_t L_size;
    in.read((char *)cs_hash, sizeof(srs_mpc_hash_t));
    in.read((char *)&H_size, sizeof(H_size));
    in.read((char *)&L_size, sizeof(L_size));

    G1 delta_g1;
    libff::alt_bn128_G1_read_compressed(in, delta_g1);
    G2 delta_g2;
    libff::alt_bn128_G2_read_compressed(in, delta_g2);

    libff::G1_vector<libff::alt_bn128_pp> H_g1(H_size);
    for (G1 &h : H_g1) {
        libff::alt_bn128_G1_read_compressed(in, h);
    }

    libff::G1_vector<libff::alt_bn128_pp> L_g1(L_size);
    for (G1 &l : L_g1) {
        libff::alt_bn128_G1_read_compressed(in, l);
    }

    srs_mpc_phase2_accumulator<libff::alt_bn128_pp> l2(
        cs_hash, delta_g1, delta_g2, std::move(H_g1), std::move(L_g1));
    check_well_formed(l2, "mpc_layer2 (read)");
    return l2;
}

} // namespace libzeth
