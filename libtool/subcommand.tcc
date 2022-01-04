// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_LIBTOOL_SUBCOMMAND_TCC__
#define __ZETH_LIBTOOL_SUBCOMMAND_TCC__

#include "libtool/subcommand.hpp"

#include <iostream>

namespace libtool
{

template<typename GlobalOptionsT>
subcommand<GlobalOptionsT>::subcommand(
    const std::string &subcommand_name, const std::string &description)
    : subcommand_name(subcommand_name), subcommand_description(description)
{
}

template<typename GlobalOptionsT> subcommand<GlobalOptionsT>::~subcommand() {}

template<typename GlobalOptionsT>
const std::string &subcommand<GlobalOptionsT>::description() const
{
    return subcommand_description;
}

template<typename GlobalOptionsT>
int subcommand<GlobalOptionsT>::execute(
    const char *argv0,
    const std::vector<std::string> command_args,
    const GlobalOptionsT &global)
{
    po::options_description options_desc("Options");
    po::options_description all_options_desc("");
    po::positional_options_description positional_options_desc;

    try {
        // Common options
        options_desc.add_options()("help,h", "This help");

        // Subcommand options
        initialize_suboptions(
            options_desc, all_options_desc, positional_options_desc);

        // Send parsed structure to subcommand-specific so it can initialize
        // itself.
        po::variables_map vm;
        po::parsed_options parsed =
            po::command_line_parser(
                std::vector<std::string>(
                    command_args.begin() + 1, command_args.end()))
                .options(all_options_desc)
                .positional(positional_options_desc)
                .run();
        po::store(parsed, vm);

        // If help was specified, print the usage and exit.
        if (vm.count("help")) {
            usage(argv0, options_desc);
            return 0;
        }

        // Otherwise, give the parsed options to the subcommand and execute.
        parse_suboptions(vm);
        return execute_subcommand(global);
    } catch (po::error &error) {
        std::cerr << "error: " << error.what() << "\n\n";
        usage(argv0, options_desc);
        return 1;
    } catch (std::invalid_argument &error) {
        std::cerr << "error: " << error.what() << "\n";
        return 1;
    }
}

template<typename GlobalOptionsT>
void subcommand<GlobalOptionsT>::usage(
    const char *argv0,
    const boost::program_options::options_description &options)
{
    subcommand_usage(argv0);
    std::cout << "\n" << description() << "\n\n";
    std::cout << options << std::endl;
}

} // namespace libtool

#endif // __ZETH_LIBTOOL_SUBCOMMAND_TCC__
