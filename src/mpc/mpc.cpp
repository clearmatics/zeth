#include "mpc_common.hpp"

#include <boost/program_options.hpp>

namespace po = boost::program_options;

extern subcommand *mpc_linear_combination_cmd;
extern subcommand *mpc_dummy_phase2_cmd;
extern subcommand *mpc_create_keypair_cmd;

int main(int argc, char **argv)
{
    ppT::init_public_params();
    po::options_description global("");
    global.add_options()("help,h", "This help")("verbose,v", "Verbose output")(
        "simple-circuit", "Use simple circuit (for testing)");

    po::options_description all("");
    all.add(global).add_options()(
        "command", po::value<std::string>(), "Command to execute")(
        "subargs",
        po::value<std::vector<std::string>>(),
        "Arguments to command");

    po::positional_options_description pos;
    pos.add("command", 1).add("subargs", -1);

    const std::map<std::string, subcommand *> commands{
        {"linear-combination", mpc_linear_combination_cmd},
        {"dummy-phase2", mpc_dummy_phase2_cmd},
        {"create-keypair", mpc_create_keypair_cmd},
    };

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

        const bool simple_circuit = (bool)vm.count("simple-circuit");

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

        sub->set_global_options(verbose, simple_circuit);
        return sub->execute(subargs);
    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        usage();
    }

    return 1;
}
