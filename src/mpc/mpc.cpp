#include "include_libsnark.hpp"

#include <boost/program_options.hpp>

namespace po = boost::program_options;

using ppT = libff::default_ec_pp;
using command_t = std::function<int(const std::vector<std::string> &)>;

int zeth_mpc_linear_combination(const std::vector<std::string> &);
int zeth_mpc_dummy_phase2(const std::vector<std::string> &);
int zeth_mpc_create_keypair(const std::vector<std::string> &);

int main(int argc, char **argv)
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

    const std::map<std::string, command_t> commands{
        {"linear-combination", zeth_mpc_linear_combination},
        {"dummy-phase2", zeth_mpc_dummy_phase2},
        {"create-keypair", zeth_mpc_create_keypair},
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

        if (0 == vm.count("command")) {
            std::cerr << "error: no command specified\n";
            usage();
            return 1;
        }

        const std::string command(vm["command"].as<std::string>());
        std::vector<std::string> subargs =
            po::collect_unrecognized(parsed.options, po::include_positional);
        subargs[0] = std::string(argv[0]) + " " + subargs[0];

        return commands.find(command)->second(subargs);
    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        usage();
    }

    return 1;
}
