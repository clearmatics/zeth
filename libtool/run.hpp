// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_LIBTOOL_RUN_HPP__
#define __ZETH_LIBTOOL_RUN_HPP__

#include "libtool/command.hpp"

namespace libtool
{

/// Execute a command object, with some global options object (initialized to
/// default values), supporting the given set of subcommands.
template<typename GlobalOptionsT>
int run_command(
    command<GlobalOptionsT> &command,
    GlobalOptionsT &options,
    const std::map<std::string, subcommand<GlobalOptionsT> *> &subcommands,
    int argc,
    char **argv);

} // namespace libtool

#include "libtool/run.tcc"

#endif // __ZETH_LIBTOOL_RUN_HPP__
