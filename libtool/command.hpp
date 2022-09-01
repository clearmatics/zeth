// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_LIBTOOL_COMMAND_HPP__
#define __ZETH_LIBTOOL_COMMAND_HPP__

#include "libtool/subcommand.hpp"

namespace libtool
{

/// Represents a top-level command, implementing parsing of global options.
template<typename GlobalOptionsT> class command
{
public:
    /// Set up global options which are valid for all subcommands.
    virtual void initialize_global_options(
        boost::program_options::options_description &global,
        boost::program_options::options_description &all_options) = 0;

    /// Parse the variables map to update the GlobalOptionsT object.
    virtual void parse_global_options(
        GlobalOptionsT &out_options,
        const boost::program_options::variables_map &vm) = 0;
};

} // namespace libtool

#endif // __ZETH_LIBTOOL_COMMAND_HPP__
