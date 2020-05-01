// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_FILESYSTEM_UTIL_HPP__
#define __ZETH_SERIALIZATION_FILESYSTEM_UTIL_HPP__

#include "libzeth/core/include_libff.hpp"

#include <assert.h>
#include <boost/filesystem.hpp>
#include <stdbool.h>
#include <stdint.h>

namespace libzeth
{

/// This function returns the path to the setup directory in which the
/// SRS will be written.
/// This function assumes that the host OS is compliant with the POSIX
/// specification since it assumes that the HOME environment variable is set.
/// See: https://pubs.opengroup.org/onlinepubs/9699919799/
boost::filesystem::path get_path_to_setup_directory();

/// This function returns the path to the debug directory used in Zeth.
/// This function assumes that the host OS is compliant with the POSIX
/// specification since it assumes that the HOME environment variable is set.
/// See: https://pubs.opengroup.org/onlinepubs/9699919799/
boost::filesystem::path get_path_to_debug_directory();

} // namespace libzeth

#endif // __ZETH_SERIALIZATION_FILESYSTEM_UTIL_HPP__
