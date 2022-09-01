// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_FILESYSTEM_UTIL_HPP__
#define __ZETH_SERIALIZATION_FILESYSTEM_UTIL_HPP__

#include <boost/filesystem.hpp>

namespace libzeth
{

/// This function returns the path to the setup directory in which the SRS will
/// be written and/or read from. It uses the ZETH_SETUP_DIR environment
/// variable, if available, falling back to ${HOME}/zeth_setup (using the POSIX
/// HOME environment variable, see:
/// https://pubs.opengroup.org/onlinepubs/9699919799/), and finally the current
/// directory.
boost::filesystem::path get_path_to_setup_directory();

/// This function returns the path to the debug directory used in Zeth. It
/// assumes that the host OS is compliant with the POSIX specification since it
/// assumes that the HOME environment variable is set. See:
/// https://pubs.opengroup.org/onlinepubs/9699919799/
boost::filesystem::path get_path_to_debug_directory();

} // namespace libzeth

#endif // __ZETH_SERIALIZATION_FILESYSTEM_UTIL_HPP__
