#ifndef __ZETH_SNARKS_GROTH16_MPC_PHASE2_TCC__
#define __ZETH_SNARKS_GROTH16_MPC_PHASE2_TCC__

#include "snarks/groth16/mpc_phase2.hpp"
#include "snarks/groth16/mpc_utils.hpp"
#include "util.hpp"

namespace libzeth
{

template<typename ppT>
srs_mpc_phase2_accumulator<ppT>::srs_mpc_phase2_accumulator(
    const libff::G1<ppT> &delta_g1,
    const libff::G2<ppT> &delta_g2,
    libff::G1_vector<ppT> &&H_g1,
    libff::G1_vector<ppT> &&L_g1)
    : delta_g1(delta_g1), delta_g2(delta_g2), H_g1(H_g1), L_g1(L_g1)
{
}

template<typename ppT>
bool srs_mpc_phase2_accumulator<ppT>::is_well_formed() const
{
    return delta_g1.is_well_formed() && delta_g2.is_well_formed() &&
           libzeth::container_is_well_formed(H_g1) &&
           libzeth::container_is_well_formed(L_g1);
}

template<typename ppT>
void srs_mpc_phase2_accumulator<ppT>::write(std::ostream &out) const
{
    using G1 = libff::G1<ppT>;
    check_well_formed(*this, "mpc_layer2 (write)");

    // Write the sizes first.

    const size_t H_size = H_g1.size();
    const size_t L_size = L_g1.size();
    out.write((const char *)&H_size, sizeof(H_size));
    out.write((const char *)&L_size, sizeof(L_size));

    out << delta_g1;
    out << delta_g2;
    for (const G1 h : H_g1) {
        out << h;
    }
    for (const G1 l : L_g1) {
        out << l;
    }
}

template<typename ppT>
srs_mpc_phase2_accumulator<ppT> srs_mpc_phase2_accumulator<ppT>::read(
    std::istream &in)
{
    using G1 = libff::G1<ppT>;

    size_t H_size;
    size_t L_size;

    in.read((char *)&H_size, sizeof(H_size));
    in.read((char *)&L_size, sizeof(L_size));

    libff::G1<ppT> delta_g1;
    libff::G2<ppT> delta_g2;
    libff::G1_vector<ppT> H_g1(H_size);
    libff::G1_vector<ppT> L_g1(L_size);

    in >> delta_g1;
    in >> delta_g2;
    for (G1 &h : H_g1) {
        in >> h;
    }
    for (G1 &l : L_g1) {
        in >> l;
    }

    srs_mpc_phase2_accumulator<ppT> l2(
        delta_g1, delta_g2, std::move(H_g1), std::move(L_g1));
    check_well_formed(l2, "mpc_layer2 (read)");
    return l2;
}

template<typename ppT>
srs_mpc_layer_C2<ppT> mpc_dummy_layer_C2(
    const srs_mpc_layer_L1<ppT> &layer1,
    const libff::Fr<ppT> &delta,
    const size_t num_inputs)
{
    using Fr = libff::Fr<ppT>;
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;
    libff::enter_block("call to mpc_dummy_layer2");

    const Fr delta_inverse = delta.inverse();
    // { H_i } = { [ t(x) . x^i / delta ]_1 } i = 0 .. n-2 (n-1 entries)
    libff::enter_block("computing H_g1");
    const size_t H_size = layer1.T_tau_powers_g1.size();
    libff::print_indent();
    printf("%zu entries\n", H_size);
    libff::G1_vector<ppT> H_g1(H_size);

#ifdef MULTICORE
#pragma omp parallel for
#endif
    for (size_t i = 0; i < H_size; ++i) {
        H_g1[i] = delta_inverse * layer1.T_tau_powers_g1[i];
    }
    libff::leave_block("computing H_g1");

    // In layer1 output, there should be num_variables+1 entries in
    // ABC_g1.  Of these:
    //
    //  - The first 1+num_inputs entries are used directly in the
    //    verification key.
    //
    //  - The remaining num_variables-num_inputs entries will be
    //    divided by delta to create layer2.
    const size_t num_variables = layer1.ABC_g1.size() - 1;
    const size_t num_L_elements = num_variables - num_inputs;
    // { L_i } = { [ ABC_i / delta ]_1 }, i = l+1 .. num_variables
    libff::enter_block("computing L_g1");
    libff::print_indent();
    printf("%zu entries\n", num_L_elements);
    libff::G1_vector<ppT> L_g1(num_L_elements);

#ifdef MULTICORE
#pragma omp parallel for
#endif
    for (size_t i = 0; i < num_L_elements; ++i) {
        L_g1[i] = delta_inverse * layer1.ABC_g1[i + num_inputs + 1];
    }
    libff::leave_block("computing L_g1");

    libff::leave_block("call to mpc_dummy_layer2");

    return srs_mpc_layer_C2<ppT>(
        delta * G1::one(), delta * G2::one(), std::move(H_g1), std::move(L_g1));
}

template<typename ppT>
libsnark::r1cs_gg_ppzksnark_keypair<ppT> mpc_create_key_pair(
    srs_powersoftau<ppT> &&pot,
    srs_mpc_layer_L1<ppT> &&layer1,
    srs_mpc_layer_C2<ppT> &&layer2,
    libsnark::r1cs_constraint_system<libff::Fr<ppT>> &&cs,
    const libsnark::qap_instance<libff::Fr<ppT>> &qap)
{
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;

    const size_t n = qap.degree();
    const size_t num_variables = qap.num_variables();
    const size_t num_inputs = qap.num_inputs();

    // Some sanity checks.
    //   layer1.A, B, C, ABC should all have num_variables+1 entries.
    //   layer2.H should have n-1 entries.
    //   layer2.L should have num_variables-num_inputs entries.
    //   pot should have degree >= n
    if (num_variables + 1 != layer1.A_g1.size()) {
        throw std::invalid_argument(
            "expected " + std::to_string(num_variables + 1) +
            " A entries, but saw " + std::to_string(layer1.A_g1.size()));
    }
    if (num_variables + 1 != layer1.B_g1.size()) {
        throw std::invalid_argument(
            "expected " + std::to_string(num_variables + 1) +
            " B_g1 entries, but saw " + std::to_string(layer1.B_g1.size()));
    }
    if (num_variables + 1 != layer1.B_g2.size()) {
        throw std::invalid_argument(
            "expected " + std::to_string(num_variables + 1) +
            " B_g2 entries, but saw " + std::to_string(layer1.B_g2.size()));
    }
    if (num_variables + 1 != layer1.ABC_g1.size()) {
        throw std::invalid_argument(
            "expected " + std::to_string(num_variables + 1) +
            " ABC entries, but saw " + std::to_string(layer1.ABC_g1.size()));
    }
    if (n - 1 != layer2.H_g1.size()) {
        throw std::invalid_argument("mismatch in degrees of layers");
    }
    if (num_variables - num_inputs != layer2.L_g1.size()) {
        throw std::invalid_argument(
            "expected " + std::to_string(num_variables - num_inputs) +
            " L entries, but saw " + std::to_string(layer2.L_g1.size()));
    }
    if (pot.tau_powers_g2.size() < n) {
        throw std::invalid_argument("insufficient POT entries");
    }

    // { ( [B_i]_2, [B_i]_1 ) } i = 0 .. num_variables
    std::vector<libsnark::knowledge_commitment<G2, G1>> B_i(num_variables + 1);
    for (size_t i = 0; i < num_variables + 1; ++i) {
        B_i[i] = libsnark::knowledge_commitment<G2, G1>(
            layer1.B_g2[i], layer1.B_g1[i]);
    }
    assert(B_i.size() == num_variables + 1);

    // [ ABC_0 ]_1,  { [ABC_i]_1 }, i = 1 .. num_inputs
    G1 ABC_0 = layer1.ABC_g1[0];
    libff::G1_vector<ppT> ABC_i(num_inputs);
    for (size_t i = 0; i < num_inputs; ++i) {
        ABC_i[i] = layer1.ABC_g1[i + 1];
    }

    libsnark::r1cs_gg_ppzksnark_verification_key<ppT> vk(
        pot.alpha_tau_powers_g1[0],
        pot.beta_g2,
        layer2.delta_g2,
        libsnark::accumulation_vector<G1>(std::move(ABC_0), std::move(ABC_i)));

    libsnark::r1cs_gg_ppzksnark_proving_key<ppT> pk(
        G1(pot.alpha_tau_powers_g1[0]),
        G1(pot.beta_tau_powers_g1[0]),
        G2(pot.beta_g2),
        G1(layer2.delta_g1),
        G2(layer2.delta_g2),
        std::move(layer1.A_g1),
        libsnark::knowledge_commitment_vector<G2, G1>(std::move(B_i)),
        std::move(layer2.H_g1),
        std::move(layer2.L_g1),
        std::move(cs));

    return libsnark::r1cs_gg_ppzksnark_keypair<ppT>(
        std::move(pk), std::move(vk));
}

template<typename ppT>
bool is_well_formed(const libsnark::r1cs_gg_ppzksnark_proving_key<ppT> &pk)
{
    if (!pk.alpha_g1.is_well_formed() || !pk.beta_g1.is_well_formed() ||
        !pk.beta_g2.is_well_formed() || !pk.delta_g1.is_well_formed() ||
        !pk.delta_g2.is_well_formed() ||
        !libzeth::container_is_well_formed(pk.A_query) ||
        !libzeth::container_is_well_formed(pk.L_query)) {
        return false;
    }

    using knowledge_commitment =
        libsnark::knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>>;
    for (const knowledge_commitment &b : pk.B_query.values) {
        if (!b.g.is_well_formed() || !b.h.is_well_formed()) {
            return false;
        }
    }

    return true;
}

template<typename ppT>
bool is_well_formed(const libsnark::r1cs_gg_ppzksnark_verification_key<ppT> &vk)
{
    if (!vk.alpha_g1.is_well_formed() || !vk.beta_g2.is_well_formed() ||
        !vk.delta_g2.is_well_formed() || !vk.ABC_g1.first.is_well_formed()) {
        return false;
    }

    return container_is_well_formed(vk.ABC_g1.rest.values);
}

template<typename ppT>
void mpc_write_keypair(
    std::ostream &out, const libsnark::r1cs_gg_ppzksnark_keypair<ppT> keypair)
{
    check_well_formed_(keypair.pk, "proving key (read)");
    check_well_formed_(keypair.vk, "verification key (read)");
    out << keypair.pk;
    out << keypair.vk;
}

template<typename ppT>
libsnark::r1cs_gg_ppzksnark_keypair<ppT> mpc_read_keypair(std::istream &in)
{
    libsnark::r1cs_gg_ppzksnark_keypair<ppT> keypair;
    in >> keypair.pk;
    in >> keypair.vk;
    check_well_formed_(keypair.pk, "proving key (read)");
    check_well_formed_(keypair.vk, "verification key (read)");
    return keypair;
}

} // namespace libzeth

#endif // __ZETH_SNARKS_GROTH16_MPC_PHASE2_TCC__
