#ifndef __ZETH_DEBUG_HELPERS_HPP__
#define __ZETH_DEBUG_HELPERS_HPP__

#include <boost/filesystem.hpp>
#include <cassert>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdbool.h>
#include <stdint.h>

// Contains definition of alt_bn128 ec public parameters
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/default_types/ec_pp.hpp>

namespace libzeth
{

libff::bigint<libff::alt_bn128_r_limbs> libsnark_bigint_from_bytes(
    const uint8_t *_x);
std::string hex_from_libsnark_bigint(
    libff::bigint<libff::alt_bn128_r_limbs> _x);
std::string point_g1_affine_as_hex(libff::alt_bn128_G1 _p);
std::string point_g2_affine_as_hex(libff::alt_bn128_G2 _p);

boost::filesystem::path get_path_to_setup_directory();
boost::filesystem::path get_path_to_debug_directory();

bool replace(std::string &str, const std::string &from, const std::string &to);

} // namespace libzeth

#endif // __ZETH_DEBUG_HELPERS_HPP__
