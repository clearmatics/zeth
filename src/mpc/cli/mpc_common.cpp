#include "mpc_common.hpp"

#include <iostream>

namespace po = boost::program_options;

subcommand::subcommand(const std::string &subcommand_name)
    : subcommand_name(subcommand_name), verbose(false), help(false)
{
}

void subcommand::set_global_options(bool verbose, ProtoboardInitFn pb_init)
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

void subcommand::init_protoboard(libsnark::protoboard<FieldT> &pb) const
{
    protoboard_init(pb);
}

void subcommand::usage(const po::options_description &options)
{
    subcommand_usage();
    std::cout << options << std::endl;
}

int mpc_main(
    int argc,
    char **argv,
    const std::map<std::string, subcommand *> &commands,
    ProtoboardInitFn pb_init)
{
    ppT::init_public_params();
    po::options_description global("");
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
        for (const auto &cmd : commands) {
            std::cout << "  " << cmd.first;
        }
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
