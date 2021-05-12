// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_TOOL_TOOL_COMMON_HPP__
#define __ZETH_TOOL_TOOL_COMMON_HPP__

#include "libtool/subcommand.hpp"

namespace zethtool
{

using global_options = bool;
using zeth_subcommand = libtool::subcommand<global_options>;

} // namespace zethtool

#endif // __ZETH_TOOL_TOOL_COMMON_HPP__
