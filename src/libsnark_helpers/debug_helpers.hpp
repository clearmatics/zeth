// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_DEBUG_HELPERS_HPP__
#define __ZETH_DEBUG_HELPERS_HPP__

#include <boost/filesystem.hpp>
#include <cassert>
#include <stdbool.h>
#include <stdint.h>

#include <libff/common/default_types/ec_pp.hpp>

namespace libzeth
{

template<typename FieldT>
std::string hex_from_libsnark_bigint(libff::bigint<FieldT::num_limbs> limbs);

template<typename FieldT>
libff::bigint<FieldT::num_limbs> libsnark_bigint_from_bytes(const uint8_t bytes[(FieldT::num_bits + 8 - 1) / 8]);

template<typename ppT>
std::string point_g1_affine_as_hex(ppT::G1_type point);

template<typename ppT>
std::string point_g2_affine_as_hex(ppT::G2_type point);

boost::filesystem::path get_path_to_setup_directory();
boost::filesystem::path get_path_to_debug_directory();

bool replace(std::string &str, const std::string &from, const std::string &to);

} // namespace libzeth

#include "libsnark_helpers/debug_helpers.hpp"

#endif // __ZETH_DEBUG_HELPERS_HPP__
