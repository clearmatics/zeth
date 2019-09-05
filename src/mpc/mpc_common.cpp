#include "mpc_common.hpp"

#include "circuit-wrapper.hpp"
#include "circuits/blake2s/blake2s_comp.hpp"
#include "test/simple_test.hpp"

#include <iostream>

namespace po = boost::program_options;

using HashTreeT = MiMC_mp_gadget<FieldT>;
using HashT = BLAKE2s_256_comp<FieldT>;

subcommand::subcommand(const std::string &subcommand_name)
    : subcommand_name(subcommand_name), verbose(false), help(false)
{
}

void subcommand::set_global_options(bool verbose, bool simple_circuit)
{
    this->verbose = verbose;
    this->simple_circuit = simple_circuit;
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

void subcommand::usage(const po::options_description &options)
{
    subcommand_usage();
    std::cout << options << std::endl;
}

void populate_protoboard(libsnark::protoboard<FieldT> &pb, bool simple_circuit)
{
    if (simple_circuit) {
        libzeth::test::simple_circuit<FieldT>(pb);
        return;
    }

    joinsplit_gadget<
        FieldT,
        HashT,
        HashTreeT,
        ZETH_NUM_JS_INPUTS,
        ZETH_NUM_JS_OUTPUTS>
        js(pb);
    js.generate_r1cs_constraints();
}
