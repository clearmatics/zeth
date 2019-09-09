#include "snarks/groth16/mpc_phase2.hpp"

namespace libzeth
{

// In the text representation, use 16 x 4-byte words, (each representated as 8
// digits + separator).
using hash_repr_word = uint32_t;
const size_t hash_repr_word_size = sizeof(hash_repr_word);
const size_t hash_repr_words_per_hash = srs_mpc_hash_size / hash_repr_word_size;

static_assert(srs_mpc_hash_size % sizeof(size_t) == 0, "invalid hash size");
static_assert(
    srs_mpc_hash_size == crypto_generichash_blake2b_BYTES_MAX,
    "unexpected hash size");

void srs_mpc_hash_init(srs_mpc_hash_state_t &state)
{
    crypto_generichash_blake2b_init(&state, nullptr, 0, srs_mpc_hash_size);
}

void srs_mpc_hash_update(
    srs_mpc_hash_state_t &state, const void *in, size_t size)
{
    crypto_generichash_blake2b_update(&state, (const uint8_t *)in, size);
}

void srs_mpc_hash_final(srs_mpc_hash_state_t &state, srs_mpc_hash_t out_hash)
{
    crypto_generichash_blake2b_final(
        &state, (uint8_t *)out_hash, srs_mpc_hash_size);
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

} // namespace libzeth
