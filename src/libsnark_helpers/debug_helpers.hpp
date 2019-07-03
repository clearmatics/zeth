#ifndef __ZETH_DEBUG_HELPERS_HPP__
#define __ZETH_DEBUG_HELPERS_HPP__

#include <stdbool.h>
#include <stdint.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cassert>
#include <iomanip>

#include <boost/filesystem.hpp>

// Contains definition of alt_bn128 ec public parameters
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <libff/common/default_types/ec_pp.hpp>

namespace libzeth {

libff::bigint<libff::alt_bn128_r_limbs> libsnarkBigintFromBytes(const uint8_t* _x);
std::string HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x);
std::string outputPointG1AffineAsHex(libff::alt_bn128_G1 _p);
std::string outputPointG2AffineAsHex(libff::alt_bn128_G2 _p);

boost::filesystem::path getPathToSetupDir();
boost::filesystem::path getPathToDebugDir();

bool replace(std::string& str, const std::string& from, const std::string& to);

} // libzeth

#endif // __ZETH_DEBUG_HELPERS_HPP__
