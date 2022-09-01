// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_LIBTOOL_TOOL_UTIL_HPP__
#define __ZETH_LIBTOOL_TOOL_UTIL_HPP__

#include "libtool/subcommand.hpp"

#include <fstream>

/// Utilities that are likely to be useful for command line tools.

namespace libtool
{

/// Utility function to open a file for reading, with appropriate flags and
/// exception handling enabled.
std::ifstream open_binary_input_file(const std::string &filename);

/// Utility function to open a binary file for writing, with appropriate flags.
std::ofstream open_binary_output_file(const std::string &filename);

} // namespace libtool

#endif // __ZETH_LIBTOOL_TOOL_UTIL_HPP__
