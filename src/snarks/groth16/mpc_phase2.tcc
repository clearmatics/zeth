#ifndef __ZETH_SNARKS_GROTH16_MPC_PHASE2_TCC__
#define __ZETH_SNARKS_GROTH16_MPC_PHASE2_TCC__

#include "libff/common/rng.hpp"
#include "snarks/groth16/mpc/chacha_rng.hpp"
#include "snarks/groth16/mpc_phase2.hpp"
#include "snarks/groth16/mpc_utils.hpp"
#include "snarks/groth16/powersoftau_utils.hpp"
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
bool srs_mpc_phase2_accumulator<ppT>::operator==(
    const srs_mpc_phase2_accumulator<ppT> &other) const
{
    return (delta_g1 == other.delta_g1) && (delta_g2 == other.delta_g2) &&
           (H_g1 == other.H_g1) && (L_g1 == other.L_g1);
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
srs_mpc_phase2_publickey<ppT>::srs_mpc_phase2_publickey(
    const srs_mpc_hash_t transcript_digest,
    const libff::G1<ppT> &new_delta_g1,
    const libff::G1<ppT> &s_g1,
    const libff::G1<ppT> &s_delta_j_g1,
    const libff::G2<ppT> &r_delta_j_g2)
    : new_delta_g1(new_delta_g1)
    , s_g1(s_g1)
    , s_delta_j_g1(s_delta_j_g1)
    , r_delta_j_g2(r_delta_j_g2)
{
    memcpy(this->transcript_digest, transcript_digest, sizeof(srs_mpc_hash_t));
}

template<typename ppT>
bool srs_mpc_phase2_publickey<ppT>::operator==(
    const srs_mpc_phase2_publickey<ppT> &other) const
{
    const bool transcript_matches = !memcmp(
        transcript_digest, other.transcript_digest, sizeof(srs_mpc_hash_t));
    return transcript_matches && (new_delta_g1 == other.new_delta_g1) &&
           (s_g1 == other.s_g1) && (s_delta_j_g1 == other.s_delta_j_g1) &&
           (r_delta_j_g2 == other.r_delta_j_g2);
}

template<typename ppT>
bool srs_mpc_phase2_publickey<ppT>::is_well_formed() const
{
    return new_delta_g1.is_well_formed() && s_g1.is_well_formed() &&
           s_delta_j_g1.is_well_formed() && r_delta_j_g2.is_well_formed();
}

template<typename ppT>
void srs_mpc_phase2_publickey<ppT>::write(std::ostream &out) const
{
    check_well_formed(*this, "srs_mpc_phase2_publickey");
    out.write((const char *)transcript_digest, sizeof(srs_mpc_hash_t));
    out << new_delta_g1 << s_g1 << s_delta_j_g1 << r_delta_j_g2;
}

template<typename ppT>
srs_mpc_phase2_publickey<ppT> srs_mpc_phase2_publickey<ppT>::read(
    std::istream &in)
{
    srs_mpc_hash_t transcript_digest;
    libff::G1<ppT> new_delta_g1;
    libff::G1<ppT> s_g1;
    libff::G1<ppT> s_delta_j_g1;
    libff::G2<ppT> r_delta_j_g2;
    in.read((char *)transcript_digest, sizeof(srs_mpc_hash_t));
    in >> new_delta_g1 >> s_g1 >> s_delta_j_g1 >> r_delta_j_g2;
    srs_mpc_phase2_publickey pubkey(
        transcript_digest, new_delta_g1, s_g1, s_delta_j_g1, r_delta_j_g2);
    check_well_formed(pubkey, "srs_mpc_phase2_publickey::read");
    return pubkey;
}

template<typename ppT>
void srs_mpc_phase2_publickey<ppT>::compute_digest(
    srs_mpc_hash_t out_digest) const
{
    hash_ostream hs;
    write(hs);
    hs.get_hash(out_digest);
}

template<typename ppT>
srs_mpc_phase2_challenge<ppT>::srs_mpc_phase2_challenge(
    const srs_mpc_hash_t transcript_digest,
    srs_mpc_phase2_accumulator<ppT> &&accumulator)
    : transcript_digest(), accumulator(accumulator)
{
    memcpy(this->transcript_digest, transcript_digest, sizeof(srs_mpc_hash_t));
}

template<typename ppT>
bool srs_mpc_phase2_challenge<ppT>::operator==(
    const srs_mpc_phase2_challenge<ppT> &other) const
{
    const bool digest_match = !memcmp(
        transcript_digest, other.transcript_digest, sizeof(srs_mpc_hash_t));
    return digest_match && (accumulator == other.accumulator);
}

template<typename ppT>
bool srs_mpc_phase2_challenge<ppT>::is_well_formed() const
{
    return accumulator.is_well_formed();
}

template<typename ppT>
void srs_mpc_phase2_challenge<ppT>::write(std::ostream &out) const
{
    check_well_formed(*this, "srs_mpc_phase2_challenge::write");
    out.write((const char *)transcript_digest, sizeof(srs_mpc_hash_t));
    accumulator.write(out);
}

template<typename ppT>
srs_mpc_phase2_challenge<ppT> srs_mpc_phase2_challenge<ppT>::read(
    std::istream &in)
{
    srs_mpc_hash_t last_response_digest;
    in.read((char *)last_response_digest, sizeof(srs_mpc_hash_t));
    srs_mpc_phase2_accumulator<ppT> accum =
        srs_mpc_phase2_accumulator<ppT>::read(in);
    srs_mpc_phase2_challenge<ppT> challenge(
        last_response_digest, std::move(accum));
    check_well_formed(challenge, "srs_mpc_phase2_challenge::read");
    return challenge;
}

template<typename ppT>
srs_mpc_phase2_response<ppT>::srs_mpc_phase2_response(
    srs_mpc_phase2_accumulator<ppT> &&new_accumulator,
    srs_mpc_phase2_publickey<ppT> &&publickey)
    : new_accumulator(new_accumulator), publickey(publickey)
{
}

template<typename ppT>
bool srs_mpc_phase2_response<ppT>::operator==(
    const srs_mpc_phase2_response<ppT> &other) const
{
    return (new_accumulator == other.new_accumulator) &&
           (publickey == other.publickey);
}

template<typename ppT> bool srs_mpc_phase2_response<ppT>::is_well_formed() const
{
    return new_accumulator.is_well_formed() && publickey.is_well_formed();
}

template<typename ppT>
void srs_mpc_phase2_response<ppT>::write(std::ostream &out) const
{
    check_well_formed(*this, "srs_mpc_phase2_response::write");
    new_accumulator.write_compressed(out);
    publickey.write(out);
}

template<typename ppT>
srs_mpc_phase2_response<ppT> srs_mpc_phase2_response<ppT>::read(
    std::istream &in)
{
    srs_mpc_phase2_accumulator<ppT> accumulator =
        srs_mpc_phase2_accumulator<ppT>::read_compressed(in);
    srs_mpc_phase2_publickey<ppT> pubkey =
        srs_mpc_phase2_publickey<ppT>::read(in);

    srs_mpc_phase2_response<ppT> response(
        std::move(accumulator), std::move(pubkey));
    check_well_formed(response, "srs_mpc_phase2_response::read");
    return response;
}

template<mp_size_t n, const libff::bigint<n> &modulus>
void srs_mpc_compute_fr(
    const srs_mpc_hash_t transcript_digest, libff::Fp_model<n, modulus> &out_fr)
{
    // Fill a U512 with random data and compute the representation mod m.
    libff::bigint<2 * n> random;
    libff::bigint<n + 1> _quotient;

    chacha_rng rng(transcript_digest, sizeof(srs_mpc_hash_t));
    rng.random(random.data, sizeof(random));
    mpn_tdiv_qr(
        _quotient.data,
        out_fr.mont_repr.data,
        0,
        random.data,
        2 * n,
        modulus.data,
        n);
}

/// Deterministically choose a value $r$ in G2, given some $s$ and $s_delta_j$
/// in G1, and the current transcript digest.
template<typename ppT>
libff::G2<ppT> srs_mpc_compute_r_g2(const srs_mpc_hash_t transcript_digest)
{
    libff::Fr<ppT> fr;
    srs_mpc_compute_fr(transcript_digest, fr);
    return fr * libff::G2<ppT>::one();
}

template<typename ppT>
srs_mpc_phase2_accumulator<ppT> srs_mpc_phase2_begin(
    const srs_mpc_layer_L1<ppT> &layer_L1, size_t num_inputs)
{
    // { H_i } = { [ t(x) . x^i / delta ]_1 } i = 0 .. n-2 (n-1 entries)
    libff::enter_block("computing initial { H_i } i=0..n-2");
    const size_t H_size = layer_L1.T_tau_powers_g1.size();
    if (!libff::inhibit_profiling_info) {
        libff::print_indent();
        printf("%zu entries\n", H_size);
    }
    libff::G1_vector<ppT> H_g1(H_size);

    libff::leave_block("computing H_g1");

    // In layer_L1 output, there should be num_variables+1 entries in
    // ABC_g1.  Of these:
    //
    //  - The first 1+num_inputs entries are used directly in the
    //    verification key.
    //
    //  - The remaining num_variables-num_inputs entries will be
    //    divided by delta to create layer2.
    const size_t num_variables = layer_L1.ABC_g1.size() - 1;
    const size_t num_L_elements = num_variables - num_inputs;
    // { L_i } = { [ ABC_i / delta ]_1 }, i = l+1 .. num_variables
    libff::enter_block("computing L_g1");
    if (!libff::inhibit_profiling_info) {
        libff::print_indent();
        printf("%zu entries\n", num_L_elements);
    }
    libff::G1_vector<ppT> L_g1(num_L_elements);

    return srs_mpc_phase2_accumulator<ppT>(
        libff::G1<ppT>::one(),
        libff::G2<ppT>::one(),
        libff::G1_vector<ppT>(layer_L1.T_tau_powers_g1),
        libff::G1_vector<ppT>(
            layer_L1.ABC_g1.begin() + num_inputs + 1, layer_L1.ABC_g1.end()));
}

template<typename ppT>
srs_mpc_phase2_publickey<ppT> srs_mpc_phase2_compute_public_key(
    const srs_mpc_hash_t transcript_digest,
    const libff::G1<ppT> &last_delta,
    const libff::Fr<ppT> &delta_j)
{
    libff::enter_block("call to srs_mpc_phase2_compute_public_key");
    const libff::G1<ppT> new_delta_g1 = delta_j * last_delta;
    const libff::G1<ppT> s_g1 = libff::G1<ppT>::random_element();
    const libff::G1<ppT> s_delta_j_g1 = delta_j * s_g1;
    const libff::G2<ppT> r_g2 = srs_mpc_compute_r_g2<ppT>(transcript_digest);
    const libff::G2<ppT> r_delta_j_g2 = delta_j * r_g2;
    libff::leave_block("call to srs_mpc_phase2_compute_public_key");

    return srs_mpc_phase2_publickey<ppT>(
        transcript_digest, new_delta_g1, s_g1, s_delta_j_g1, r_delta_j_g2);
}

template<typename ppT>
bool srs_mpc_phase2_verify_publickey(
    const libff::G1<ppT> last_delta_g1,
    const srs_mpc_phase2_publickey<ppT> &publickey,
    libff::G2<ppT> &out_r_g2)
{
    const libff::G1<ppT> &s_g1 = publickey.s_g1;
    const libff::G1<ppT> &s_delta_j_g1 = publickey.s_delta_j_g1;
    out_r_g2 = srs_mpc_compute_r_g2<ppT>(publickey.transcript_digest);
    const libff::G2<ppT> &r_delta_j_g2 = publickey.r_delta_j_g2;
    const libff::G1<ppT> &new_delta_g1 = publickey.new_delta_g1;

    // Step 1 (from [BoweGM17]).  Check the proof of knowledge.
    if (!same_ratio<ppT>(s_g1, s_delta_j_g1, out_r_g2, r_delta_j_g2)) {
        return false;
    }

    // Step 2.  Check new_delta_g1 is correct.
    if (!same_ratio<ppT>(last_delta_g1, new_delta_g1, out_r_g2, r_delta_j_g2)) {
        return false;
    }

    return true;
}

template<typename ppT>
bool srs_mpc_phase2_verify_publickey(
    const libff::G1<ppT> last_delta_g1,
    const srs_mpc_phase2_publickey<ppT> &publickey)
{
    libff::G2<ppT> r_g2;
    return srs_mpc_phase2_verify_publickey<ppT>(last_delta_g1, publickey, r_g2);
}

template<typename ppT>
srs_mpc_phase2_accumulator<ppT> srs_mpc_phase2_update_accumulator(
    const srs_mpc_phase2_accumulator<ppT> &last_accum,
    const libff::Fr<ppT> &delta_j)
{
    libff::enter_block("call to srs_mpc_phase2_update_accumulator");
    const libff::Fr<ppT> delta_j_inverse = delta_j.inverse();

    // Step 3 (from [BoweGM17]): Update accumulated $\delta$
    const libff::G1<ppT> new_delta_g1 = delta_j * last_accum.delta_g1;
    const libff::G2<ppT> new_delta_g2 = delta_j * last_accum.delta_g2;

    // Step3: Update $L_i$ by dividing by $\delta$ ('K' in the paper, but we
    // use L here to be consistent with the final keypair in libsnark).
    libff::enter_block("updating L_g1");
    const size_t num_L_elements = last_accum.L_g1.size();
    if (!libff::inhibit_profiling_info) {
        libff::print_indent();
        printf("%zu entries\n", num_L_elements);
    }
    libff::G1_vector<ppT> L_g1(num_L_elements);
#ifdef MULTICORE
#pragma omp parallel for
#endif
    for (size_t i = 0; i < num_L_elements; ++i) {
        L_g1[i] = delta_j_inverse * last_accum.L_g1[i];
    }
    putchar('\n');
    libff::leave_block("updating L_g1");

    // Step 5: Update $H_i$ by dividing by our contribution.
    libff::enter_block("updating H_g1");
    const size_t H_size = last_accum.H_g1.size();
    if (!libff::inhibit_profiling_info) {
        libff::print_indent();
        printf("%zu entries\n", H_size);
    }
    libff::G1_vector<ppT> H_g1(H_size);
#ifdef MULTICORE
#pragma omp parallel for
#endif
    for (size_t i = 0; i < H_size; ++i) {
        H_g1[i] = delta_j_inverse * last_accum.H_g1[i];
    }
    libff::leave_block("updating H_g1");

    libff::leave_block("call to srs_mpc_phase2_update_accumulator");

    return srs_mpc_phase2_accumulator<ppT>(
        new_delta_g1, new_delta_g2, std::move(H_g1), std::move(L_g1));
}

template<typename ppT>
bool srs_mpc_phase2_update_is_consistent(
    const srs_mpc_phase2_accumulator<ppT> &last,
    const srs_mpc_phase2_accumulator<ppT> &updated)
{
    libff::enter_block("call to srs_mpc_phase2_update_is_consistent");

    // Check basic compatibility between 'last' and 'updated'
    if (last.H_g1.size() != updated.H_g1.size() ||
        last.L_g1.size() != updated.L_g1.size()) {
        return false;
    }

    const libff::G2<ppT> &old_delta_g2 = last.delta_g2;
    const libff::G2<ppT> &new_delta_g2 = updated.delta_g2;

    // Check that, that the delta_g1 and delta_2 ratios match.
    if (!same_ratio<ppT>(
            last.delta_g1, updated.delta_g1, old_delta_g2, new_delta_g2)) {
        return false;
    }

    // Step 3.  Check that the updates to L values are consistent.  Each
    // entry should have been divided by $\delta_j$, so SameRatio((updated,
    // last), (old_delta_g2, new_delta_g2)) should hold.
    if (!same_ratio_vectors<ppT>(
            updated.L_g1, last.L_g1, old_delta_g2, new_delta_g2)) {
        return false;
    }

    // Step 4.  Similar consistency checks for H
    if (!same_ratio_vectors<ppT>(
            updated.H_g1, last.H_g1, old_delta_g2, new_delta_g2)) {
        return false;
    }

    libff::leave_block("call to srs_mpc_phase2_update_is_consistent");

    return true;
}

template<typename ppT>
bool srs_mpc_phase2_verify_update(
    const srs_mpc_phase2_accumulator<ppT> &last,
    const srs_mpc_phase2_accumulator<ppT> &updated,
    const srs_mpc_phase2_publickey<ppT> &publickey)
{
    // Step 1 and 2 (from [BoweGM17]).  Check the proof-of-knowledge in the
    // public key, and the updated delta value.  Obtain r_g2 to avoid
    // recomputing it.
    libff::G2<ppT> r_g2;
    if (!srs_mpc_phase2_verify_publickey(last.delta_g1, publickey, r_g2)) {
        return false;
    }

    if (publickey.new_delta_g1 != updated.delta_g1) {
        return false;
    }

    return srs_mpc_phase2_update_is_consistent(last, updated);
}

template<typename ppT>
srs_mpc_phase2_challenge<ppT> srs_mpc_phase2_initial_challenge(
    srs_mpc_phase2_accumulator<ppT> &&accumulator)
{
    srs_mpc_hash_t initial_transcript_digest;
    const uint8_t empty[0]{};
    srs_mpc_compute_hash(initial_transcript_digest, empty, 0);
    return srs_mpc_phase2_challenge<ppT>(
        initial_transcript_digest, std::move(accumulator));
}

template<typename ppT>
srs_mpc_phase2_response<ppT> srs_mpc_phase2_compute_response(
    const srs_mpc_phase2_challenge<ppT> &challenge,
    const libff::Fr<ppT> &delta_j)
{
    libff::enter_block("computing contribution public key");
    srs_mpc_phase2_publickey<ppT> pubkey =
        srs_mpc_phase2_compute_public_key<ppT>(
            challenge.transcript_digest,
            challenge.accumulator.delta_g1,
            delta_j);
    libff::leave_block("computing contribution public key");

    srs_mpc_phase2_accumulator<ppT> new_accum =
        srs_mpc_phase2_update_accumulator(challenge.accumulator, delta_j);

    return srs_mpc_phase2_response<ppT>(
        std::move(new_accum), std::move(pubkey));
}

template<typename ppT>
bool srs_mpc_phase2_verify_response(
    const srs_mpc_phase2_challenge<ppT> &challenge,
    const srs_mpc_phase2_response<ppT> &response)
{
    // Ensure that response.pubkey corresponsds to challenge.transcript_digest
    const bool digest_match = !memcmp(
        challenge.transcript_digest,
        response.publickey.transcript_digest,
        sizeof(srs_mpc_hash_t));
    if (!digest_match) {
        return false;
    }

    return srs_mpc_phase2_verify_update(
        challenge.accumulator, response.new_accumulator, response.publickey);
}

template<typename ppT>
srs_mpc_phase2_challenge<ppT> srs_mpc_phase2_compute_challenge(
    srs_mpc_phase2_response<ppT> &&response)
{
    srs_mpc_hash_t new_transcript_digest;
    response.publickey.compute_digest(new_transcript_digest);
    return srs_mpc_phase2_challenge<ppT>(
        new_transcript_digest, std::move(response.new_accumulator));
}

template<typename ppT, bool enable_contribution_check>
bool srs_mpc_phase2_verify_transcript(
    const srs_mpc_hash_t initial_transcript_digest,
    const libff::G1<ppT> &initial_delta,
    const srs_mpc_hash_t check_for_contribution,
    std::istream &transcript_stream,
    libff::G1<ppT> &out_final_delta,
    srs_mpc_hash_t out_final_transcript_digest,
    bool &out_contribution_found)
{
    srs_mpc_hash_t digest;
    memcpy(digest, initial_transcript_digest, sizeof(srs_mpc_hash_t));
    libff::G1<ppT> delta = initial_delta;

    bool contribution_found = false;
    while (EOF != transcript_stream.peek()) {
        const srs_mpc_phase2_publickey<ppT> publickey =
            srs_mpc_phase2_publickey<ppT>::read(transcript_stream);

        const bool digests_match = !memcmp(
            digest, publickey.transcript_digest, sizeof(srs_mpc_hash_t));
        if (!digests_match) {
            return false;
        }

        publickey.compute_digest(digest);
        if (enable_contribution_check && !contribution_found &&
            0 == memcmp(
                     digest, check_for_contribution, sizeof(srs_mpc_hash_t))) {
            contribution_found = true;
        }

        if (!srs_mpc_phase2_verify_publickey(delta, publickey)) {
            return false;
        }

        // Contribution is valid.  Update state and read next publickey.
        delta = publickey.new_delta_g1;
    }

    out_final_delta = delta;
    memcpy(out_final_transcript_digest, digest, sizeof(srs_mpc_hash_t));
    if (enable_contribution_check) {
        out_contribution_found = contribution_found;
    }

    return true;
}

template<typename ppT>
bool srs_mpc_phase2_verify_transcript(
    const srs_mpc_hash_t initial_transcript_digest,
    const libff::G1<ppT> &initial_delta,
    std::istream &transcript_stream,
    libff::G1<ppT> &out_final_delta,
    srs_mpc_hash_t out_final_transcript_digest)
{
    const srs_mpc_hash_t dummy_check_for_contribution{};
    bool dummy_out_contribution_found;
    return srs_mpc_phase2_verify_transcript<ppT, false>(
        initial_transcript_digest,
        initial_delta,
        dummy_check_for_contribution,
        transcript_stream,
        out_final_delta,
        out_final_transcript_digest,
        dummy_out_contribution_found);
}

template<typename ppT>
srs_mpc_phase2_challenge<ppT> srs_mpc_dummy_phase2(
    const srs_mpc_layer_L1<ppT> &layer1,
    const libff::Fr<ppT> &delta,
    const size_t num_inputs)
{
    // Start with a blank challenge and simulate one contribution of the MPC
    // using delta.
    srs_mpc_phase2_challenge<ppT> challenge_0 =
        srs_mpc_phase2_initial_challenge(
            srs_mpc_phase2_begin(layer1, num_inputs));
    srs_mpc_phase2_response<ppT> response_1 =
        srs_mpc_phase2_compute_response(challenge_0, delta);
    return srs_mpc_phase2_compute_challenge(std::move(response_1));
}

template<typename ppT>
libsnark::r1cs_gg_ppzksnark_keypair<ppT> mpc_create_key_pair(
    srs_powersoftau<ppT> &&pot,
    srs_mpc_layer_L1<ppT> &&layer1,
    srs_mpc_phase2_accumulator<ppT> &&layer2,
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
