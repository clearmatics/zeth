#include "snarks/groth16/mpc_phase2.hpp"

namespace libzeth
{

// In the text representation, use 16 x 4-byte words, (each representated as 8
// digits + separator).
using hash_repr_word = uint32_t;
const size_t hash_repr_word_size = sizeof(hash_repr_word);
const size_t hash_repr_words_per_hash = srs_mpc_hash_size / hash_repr_word_size;

static_assert(srs_mpc_hash_size % sizeof(size_t) == 0, "invalid hash size");
static_assert(srs_mpc_hash_size == BLAKE2B_OUTBYTES, "unexpected hash size");

void srs_mpc_hash_init(srs_mpc_hash_state_t &state)
{
    blake2b_init(&state, BLAKE2B_OUTBYTES);
}

void srs_mpc_hash_update(
    srs_mpc_hash_state_t &state, const void *in, size_t size)
{
    blake2b_update(&state, in, size);
}

void srs_mpc_hash_final(srs_mpc_hash_state_t &state, srs_mpc_hash_t out_hash)
{
    blake2b_final(&state, out_hash, srs_mpc_hash_size);
}

void srs_mpc_compute_hash(
    srs_mpc_hash_t out_hash, const void *data, size_t data_size)
{
    srs_mpc_hash_state_t s;
    srs_mpc_hash_init(s);
    srs_mpc_hash_update(s, data, data_size);
    srs_mpc_hash_final(s, out_hash);
}

void srs_mpc_compute_hash(srs_mpc_hash_t out_hash, const std::string &data)
{
    srs_mpc_compute_hash(out_hash, data.data(), data.size());
}

void srs_mpc_hash_write(const srs_mpc_hash_t hash, std::ostream &out)
{
    const hash_repr_word *words = (const hash_repr_word *)hash;

    for (size_t i = 0; i < hash_repr_words_per_hash; ++i) {
        char sep = ((i % 4) == 3) ? '\n' : ' ';
        out << binary_str_to_hexadecimal_str(&words[i], sizeof(words[i]))
            << sep;
    }
}

bool srs_mpc_hash_read(srs_mpc_hash_t out_hash, std::istream &in)
{
    hash_repr_word *out_data = (hash_repr_word *)out_hash;

    std::string word;
    for (size_t i = 0; i < hash_repr_words_per_hash; ++i) {
        if (!(in >> word)) {
            std::cerr << "Read failed" << std::endl;
            return false;
        }

        const std::string bin = hexadecimal_str_to_binary_str(word);
        if (bin.size() != hash_repr_word_size) {
            std::cerr << "Invalid word size" << std::endl;
            return false;
        }

        memcpy(&out_data[i], bin.data(), hash_repr_word_size);
    }

    return true;
}

hash_streambuf::hash_streambuf() { srs_mpc_hash_init(hash_state); }

std::streamsize hash_streambuf::xsputn(const char *s, std::streamsize n)
{
    srs_mpc_hash_update(hash_state, s, n);
    return n;
}

hash_ostream::hash_ostream() : std::ostream(&hsb), hsb() {}

void hash_ostream::get_hash(srs_mpc_hash_t out_hash)
{
    srs_mpc_hash_final(hsb.hash_state, out_hash);
}

template<>
void srs_mpc_phase2_accumulator<libff::alt_bn128_pp>::write_compressed(
    std::ostream &out) const
{
    using G1 = libff::alt_bn128_G1;
    check_well_formed(*this, "mpc_layer2 (write)");

    // Write the sizes first.

    const size_t H_size = H_g1.size();
    const size_t L_size = L_g1.size();
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

template<>
srs_mpc_phase2_accumulator<libff::alt_bn128_pp> srs_mpc_phase2_accumulator<
    libff::alt_bn128_pp>::read_compressed(std::istream &in)
{
    using G1 = libff::alt_bn128_G1;
    using G2 = libff::alt_bn128_G2;

    size_t H_size;
    size_t L_size;
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
        delta_g1, delta_g2, std::move(H_g1), std::move(L_g1));
    check_well_formed(l2, "mpc_layer2 (read)");
    return l2;
}

} // namespace libzeth
