// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_LIBTOOL_RUN_TCC__
#define __ZETH_LIBTOOL_RUN_TCC__

#include "libtool/run.hpp"

namespace libtool
{

namespace internal
{

template<typename GlobalOptionsT>
void print_usage(
    const char *const *argv,
    const po::options_description &options,
    const std::map<std::string, subcommand<GlobalOptionsT> *> &subcommands)
{
    std::cout << "Usage:\n"
              << "  " << argv[0] << " [OPTIONS] COMMAND [ARGS] ...\n\n"
              << options;

    std::cout << "\nCommands:\n";

    // list_commands(commands);
    using entry_t = std::pair<std::string, subcommand<GlobalOptionsT> *>;

    // +4 here to ensure minimal space between command name and description
    const size_t cmd_name_padded =
        4 + std::max_element(
                subcommands.begin(),
                subcommands.end(),
                [](const entry_t &a, const entry_t &b) {
                    return a.first.size() < b.first.size();
                })
                ->first.size();

    for (const auto &cmd : subcommands) {
        const size_t padding = cmd_name_padded - cmd.first.size();
        std::cout << "  " << cmd.first << std::string(padding, ' ')
                  << cmd.second->description() << "\n";
    }

    std::cout << std::endl;
}

template<typename GlobalOptionsT>
int run_subcommand(
    const std::map<std::string, subcommand<GlobalOptionsT> *> &subcommands,
    const std::string &command_name,
    const char *argv0,
    const std::vector<std::string> &command_args,
    const GlobalOptionsT &global_options)
{
    const typename std::map<std::string, subcommand<GlobalOptionsT> *>::
        const_iterator sub_it = subcommands.find(command_name);
    if (sub_it == subcommands.end()) {
        throw po::error("invalid command");
    }

    subcommand<GlobalOptionsT> *sub = sub_it->second;
    return sub->execute(argv0, command_args, global_options);
}

} // namespace internal

template<typename GlobalOptionsT>
int run_command(
    command<GlobalOptionsT> &command,
    GlobalOptionsT &options,
    const std::map<std::string, subcommand<GlobalOptionsT> *> &subcommands,
    int argc,
    char **argv)
{
    po::options_description global("Global options");
    po::options_description all("");

    // Default --help option
    global.add_options()("help,h", "Show this help message and exit");

    // Global options
    command.initialize_global_options(global, all);

    // Add a single positional "command" option.
    po::positional_options_description pos;
    all.add_options()(
        "command", po::value<std::string>(), "Command to execute")(
        "subargs",
        po::value<std::vector<std::string>>(),
        "Arguments to command");
    pos.add("command", 1).add("subargs", -1);

    auto usage = [&argv, &global, &subcommands]() {
        internal::print_usage<GlobalOptionsT>(argv, global, subcommands);
    };

    try {
        po::variables_map vm;
        po::parsed_options parsed = po::command_line_parser(argc, argv)
                                        .options(all)
                                        .positional(pos)
                                        .allow_unregistered()
                                        .run();
        po::store(parsed, vm);

        const bool help_flag = (bool)vm.count("help");

        // If no command was given, print the top-level usage message. If a
        // help flag was specified, exit normally, otherwise print an error
        // message and exit with error. (If a command was given, the help flag
        // is passed to the subcommand).
        if (!vm.count("command")) {
            if (help_flag) {
                usage();
                return 0;
            }
            std::cerr << "error: no command specified\n";
            usage();
            return 1;
        }

        // Parse the global options
        command.parse_global_options(options, vm);

        // Execute the subcommand
        const std::string subcommand(vm["command"].as<std::string>());
        std::vector<std::string> subargs =
            po::collect_unrecognized(parsed.options, po::include_positional);
        subargs[0] = std::string(argv[0]) + " " + subargs[0];

        // Add the --help flag back, if given (it was absorbed by the global
        // parser above).
        if (help_flag) {
            subargs.push_back("--help");
        }

        return internal::run_subcommand(
            subcommands, subcommand, argv[0], subargs, options);
    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        usage();
    }

    return 1;
}

} // namespace libtool

#endif // __ZETH_LIBTOOL_RUN_TCC__
