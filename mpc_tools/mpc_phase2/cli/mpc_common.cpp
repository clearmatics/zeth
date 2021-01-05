// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "mpc_common.hpp"

#include <iostream>

namespace po = boost::program_options;

subcommand::subcommand(
    const std::string &subcommand_name, const std::string &description)
    : subcommand_name(subcommand_name)
    , subcommand_description(description)
    , verbose(false)
    , help(false)
{
}

void subcommand::set_global_options(
    bool verbose, const ProtoboardInitFn &pb_init)
{
    this->verbose = verbose;
    this->protoboard_init = pb_init;
}

int subcommand::execute(const std::vector<std::string> &args)
{
    po::options_description options_desc("Options");
    po::options_description all_options_desc("");
    po::positional_options_description positional_options_desc;

    try {
        options_desc.add_options()("help,h", "This help"),
            initialize_suboptions(
                options_desc, all_options_desc, positional_options_desc);

        po::variables_map vm;
        po::parsed_options parsed =
            po::command_line_parser(
                std::vector<std::string>(args.begin() + 1, args.end()))
                .options(all_options_desc)
                .positional(positional_options_desc)
                .run();
        po::store(parsed, vm);
        parse_suboptions(vm);

        if (vm.count("help")) {
            help = true;
            usage(options_desc);
            return 0;
        }
    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        usage(options_desc);
        return 1;
    }

    // Execute and handle errors
    try {
        return execute_subcommand();
    } catch (std::invalid_argument &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        return 1;
    }
}

const std::string &subcommand::description() const
{
    return subcommand_description;
}

void subcommand::init_protoboard(libsnark::protoboard<Field> &pb) const
{
    protoboard_init(pb);
}

void subcommand::usage(const po::options_description &options)
{
    subcommand_usage();
    std::cout << description() << "\n\n";
    std::cout << options << std::endl;
}

void list_commands(const std::map<std::string, subcommand *> &commands)
{
    using entry_t = std::pair<std::string, subcommand *>;
    const size_t cmd_name_padded =
        4 + std::max_element(
                commands.begin(),
                commands.end(),
                [](const entry_t &a, const entry_t &b) {
                    return a.first.size() < b.first.size();
                })
                ->first.size();

    for (const auto &cmd : commands) {
        const size_t padding = cmd_name_padded - cmd.first.size();
        std::cout << "  " << cmd.first << std::string(padding, ' ')
                  << cmd.second->description() << "\n";
    }
}

int mpc_main(
    int argc,
    char **argv,
    const std::map<std::string, subcommand *> &commands,
    const ProtoboardInitFn &pb_init)
{
    libzeth::defaults::pp::init_public_params();
    po::options_description global("Global options");
    global.add_options()("help,h", "This help")("verbose,v", "Verbose output");

    po::options_description all("");
    all.add(global).add_options()(
        "command", po::value<std::string>(), "Command to execute")(
        "subargs",
        po::value<std::vector<std::string>>(),
        "Arguments to command");

    po::positional_options_description pos;
    pos.add("command", 1).add("subargs", -1);

    auto usage = [&argv, &global, &commands]() {
        std::cout << "Usage:\n"
                  << "  " << argv[0]
                  << " [<options>] <command> <command-arguments> ...\n\n"
                  << global;

        std::cout << "\nCommands:\n";
        list_commands(commands);
        std::cout << std::endl;
    };

    try {
        po::variables_map vm;
        po::parsed_options parsed = po::command_line_parser(argc, argv)
                                        .options(all)
                                        .positional(pos)
                                        .allow_unregistered()
                                        .run();
        po::store(parsed, vm);

        if (vm.count("help")) {
            usage();
            return 0;
        }

        const bool verbose = (bool)vm.count("verbose");
        if (!verbose) {
            libff::inhibit_profiling_info = true;
            libff::inhibit_profiling_counters = true;
        }

        if (0 == vm.count("command")) {
            std::cerr << "error: no command specified\n";
            usage();
            return 1;
        }

        const std::string command(vm["command"].as<std::string>());
        std::vector<std::string> subargs =
            po::collect_unrecognized(parsed.options, po::include_positional);
        subargs[0] = std::string(argv[0]) + " " + subargs[0];

        subcommand *sub = commands.find(command)->second;
        if (sub == nullptr) {
            throw po::error("invalid command");
        }

        sub->set_global_options(verbose, pb_init);
        return sub->execute(subargs);
    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        usage();
    }

    return 1;
}
