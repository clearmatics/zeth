// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_LIBTOOL_SUBCOMMAND_HPP__
#define __ZETH_LIBTOOL_SUBCOMMAND_HPP__

#include <boost/program_options.hpp>
#include <map>
#include <string>

namespace po = boost::program_options;

namespace libtool
{

/// Class representing a tool subcommand.
template<typename GlobalOptionsT> class subcommand
{
public:
    subcommand(
        const std::string &subcommand_name, const std::string &description);
    virtual ~subcommand();
    const std::string &description() const;

    /// Common code to parse options and invoke the virtual execute entrypoint.
    int execute(
        const char *argv0,
        const std::vector<std::string> command_args,
        const GlobalOptionsT &global);

protected:
    void usage(
        const char *argv0,
        const boost::program_options::options_description &options);

    /// Instantiation can now set up the boost program_options structures.
    virtual void initialize_suboptions(
        boost::program_options::options_description &options,
        boost::program_options::options_description &all_options,
        boost::program_options::positional_options_description &pos) = 0;

    /// Instantiation can record any command-specific information from the
    /// parsed variables_map.
    virtual void parse_suboptions(
        const boost::program_options::variables_map &vm) = 0;

    /// Any command-specific output for usage.
    virtual void subcommand_usage(const char *argv0) = 0;

    /// Execute the command using global options defined by the caller.
    virtual int execute_subcommand(const GlobalOptionsT &global) = 0;

    std::string subcommand_name;
    std::string subcommand_description;
};

} // namespace libtool

#include "libtool/subcommand.tcc"

#endif // __ZETH_LIBTOOL_SUBCOMMAND_HPP__
