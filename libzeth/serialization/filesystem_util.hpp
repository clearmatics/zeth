// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_FILESYSTEM_UTIL_HPP__
#define __ZETH_SERIALIZATION_FILESYSTEM_UTIL_HPP__

#include <boost/filesystem.hpp>
#include <cassert>
#include <libff/common/default_types/ec_pp.hpp>
#include <stdbool.h>
#include <stdint.h>

namespace libzeth
{

boost::filesystem::path get_path_to_setup_directory();
boost::filesystem::path get_path_to_debug_directory();

} // namespace libzeth

#endif // __ZETH_SERIALIZATION_FILESYSTEM_UTIL_HPP__
