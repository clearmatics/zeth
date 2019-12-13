// DISCLAIMER:
// Content taken and adapted from:
// wraplibsnark.cpp (originally written by Jacob Eberhardt and Dennis Kuhnert)

#include "libsnark_helpers/debug_helpers.hpp"

#include "util.hpp"

namespace libzeth
{

// Conversion byte[32] <-> libsnark bigint.
libff::bigint<libff::alt_bn128_r_limbs> libsnark_bigint_from_bytes(
    const uint8_t *_x)
{
    libff::bigint<libff::alt_bn128_r_limbs> x;

    for (unsigned i = 0; i < 4; i++) {
        for (unsigned j = 0; j < 8; j++) {
            x.data[3 - i] |= uint64_t(_x[i * 8 + j]) << (8 * (7 - j));
        }
    }
    return x;
}

std::string hex_from_libsnark_bigint(libff::bigint<libff::alt_bn128_r_limbs> _x)
{
    uint8_t x[32];
    for (unsigned i = 0; i < 4; i++) {
        for (unsigned j = 0; j < 8; j++) {
            x[i * 8 + j] = uint8_t(uint64_t(_x.data[3 - i]) >> (8 * (7 - j)));
        }
    }

    std::stringstream ss;
    ss << std::setfill('0');
    for (unsigned i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << (int)x[i];
    }

    std::string str = ss.str();
    return str.erase(0, std::min(str.find_first_not_of('0'), str.size() - 1));
}

std::string point_g1_affine_as_hex(libff::alt_bn128_G1 _p)
{
    libff::alt_bn128_G1 aff = _p;
    aff.to_affine_coordinates();
    return "\"0x" + hex_from_libsnark_bigint(aff.X.as_bigint()) + "\", \"0x" +
           hex_from_libsnark_bigint(aff.Y.as_bigint()) + "\"";
}

std::string point_g2_affine_as_hex(libff::alt_bn128_G2 _p)
{
    libff::alt_bn128_G2 aff = _p;
    aff.to_affine_coordinates();
    return "[\"0x" + hex_from_libsnark_bigint(aff.X.c1.as_bigint()) +
           "\", \"0x" + hex_from_libsnark_bigint(aff.X.c0.as_bigint()) +
           "\"],\n [\"0x" + hex_from_libsnark_bigint(aff.Y.c1.as_bigint()) +
           "\", \"0x" + hex_from_libsnark_bigint(aff.Y.c0.as_bigint()) + "\"]";
}

boost::filesystem::path get_path_to_setup_directory()
{
    const char *path = std::getenv("ZETH_TRUSTED_SETUP_DIR");
    if (nullptr == path) {
        // Fallback destination if the ZETH_TRUSTED_SETUP_DIR env var is not set
        return "../trusted_setup";
    }

    return boost::filesystem::path(path);
}

boost::filesystem::path get_path_to_debug_directory()
{
    const char *path_to_debug_directory = std::getenv("ZETH_DEBUG_DIR");
    if (path_to_debug_directory == NULL) {
        // Fallback destination if the ZETH_DEBUG_DIR env var is not set
        path_to_debug_directory = "../debug";
    }

    boost::filesystem::path setup_dir(path_to_debug_directory);
    return setup_dir;
}

bool replace(std::string &str, const std::string &from, const std::string &to)
{
    size_t start_pos = str.find(from);
    if (start_pos == std::string::npos) {
        return false;
    }

    str.replace(start_pos, from.length(), to);
    return true;
}

} // namespace libzeth
