// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

/// Small utility to check powersoftau output and to compute the evaluation of
/// Lagrange polynomials at tau.

#include "libzeth/mpc/groth16/powersoftau_utils.hpp"
#include "zeth_config.h"

#include <boost/program_options.hpp>
#include <fstream>

using namespace libzeth;
using pp = defaults::pp;
namespace po = boost::program_options;

// -----------------------------------------------------------------------------
// cli_options
// -----------------------------------------------------------------------------

// Usage:
//     pot-process [<options>] <powersoftau file> <degree>
//
// Options:
//     -h,--help              This message
//     -v,--verbose           Verbose
//     --check                Check pot well-formedness and exit
//     --out <file>           Write the lagrange polynomial values to this file
//                            ("lagrange-radix2-<n>")
//     --lagrange-degree <l>  Use degree l instead of n (l < n)
//     --dummy                Create dummy powersoftau data (for testing only!)
class cli_options
{
public:
    po::options_description desc;
    po::options_description all_desc;
    po::positional_options_description pos;

    std::string command;
    bool help;
    std::string powersoftau_file;
    size_t degree;
    bool verbose;
    bool check;
    bool dummy;
    std::string out;
    size_t lagrange_degree;

    cli_options();
    void parse(int argc, char **argv);
    void usage() const;
};

cli_options::cli_options()
    : desc("Options")
    , all_desc("")
    , pos()
    , command("pot-process")
    , help(false)
    , powersoftau_file()
    , degree(0)
    , verbose(false)
    , check(false)
    , dummy(false)
    , out()
    , lagrange_degree(0)
{
    desc.add_options()("help,h", "This help")("verbose,v", "Verbose output")(
        "check", "Check pot well-formedness and exit")(
        "out,o", po::value<std::string>(), "Output file")(
        "lagrange-degree", po::value<size_t>(), "Use degree l")(
        "dummy", "Create dummy powersoftau data (!for testing only)");
    all_desc.add(desc).add_options()(
        "powersoftau_file", po::value<std::string>(), "powersoftau file")(
        "degree", po::value<size_t>(), "degree");
    pos.add("powersoftau_file", 1).add("degree", 1);
}

void cli_options::usage() const
{
    std::cout << "Usage:" << std::endl
              << "  " << command
              << " [<options>] <powersoftau file> <degree>\n\n"
              << desc << std::endl;
}

void cli_options::parse(int argc, char **argv)
{
    po::variables_map vm;
    po::parsed_options parsed = po::command_line_parser(argc, argv)
                                    .options(all_desc)
                                    .positional(pos)
                                    .run();
    po::store(parsed, vm);

    command = argv[0];

    if (vm.count("help")) {
        help = true;
        return;
    }

    if (0 == vm.count("powersoftau_file")) {
        throw po::error("powersoftau_file not specified");
    }
    if (0 == vm.count("degree")) {
        throw po::error("degree not specified");
    }

    powersoftau_file = vm["powersoftau_file"].as<std::string>();
    verbose = vm.count("verbose");
    check = vm.count("check");
    degree = vm["degree"].as<size_t>();
    lagrange_degree = vm.count("lagrange-degree")
                          ? vm["lagrange-degree"].as<size_t>()
                          : degree;
    out = vm.count("out") ? vm["out"].as<std::string>()
                          : "lagrange-" + std::to_string(lagrange_degree);
    dummy = vm.count("dummy");

    if (dummy && check) {
        throw po::error("specify at most one of --dummy and --check");
    }
}

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------

static int powersoftau_main(const cli_options &options)
{
    // Initialize
    if (options.help) {
        options.usage();
        return 0;
    }

    if (options.verbose) {
        std::cout << " command: " << options.command << "\n";
        std::cout << " help: " << std::to_string(options.help) << "\n";
        std::cout << " powersoftau_file: " << options.powersoftau_file << "\n";
        std::cout << " degree: " << std::to_string(options.degree) << "\n";
        std::cout << " verbose: " << std::to_string(options.verbose) << "\n";
        std::cout << " check: " << std::to_string(options.check) << std::endl;
        std::cout << " out: " << options.out << "\n";
        std::cout << " lagrange_degree: "
                  << std::to_string(options.lagrange_degree) << std::endl;
    }

    pp::init_public_params();
    if (!options.verbose) {
        libff::inhibit_profiling_counters = true;
        libff::inhibit_profiling_info = true;
    }

    // If --dummy options was given, create a powersoftau struct from
    // local randomness, write it out and return.
    if (options.dummy) {
        const srs_powersoftau<pp> dummy = dummy_powersoftau<pp>(options.degree);
        std::cout << "Writing locally constructed powersoftau to "
                  << options.powersoftau_file << " ... ";
        std::ofstream out(
            options.powersoftau_file,
            std::ios_base::binary | std::ios_base::out);
        powersoftau_write(out, dummy);

        std::cout << "DONE" << std::endl;
        return 0;
    }

    // Read in powersoftau
    std::ifstream in(
        options.powersoftau_file, std::ios_base::binary | std::ios_base::in);
    const srs_powersoftau<pp> powersoftau =
        powersoftau_load<pp>(in, options.degree);
    in.close();

    // If --check was given, run the well-formedness check and stop.
    if (options.check) {
        if (!powersoftau_is_well_formed(powersoftau)) {
            std::cerr << "Invalid powersoftau file" << std::endl;
            return 1;
        }

        std::cout << "powersoftau file is valid" << std::endl;
        return 0;
    }

    srs_lagrange_evaluations<pp> lagrange =
        powersoftau_compute_lagrange_evaluations(
            powersoftau, options.lagrange_degree);

    std::cout << "Writing Lagrange polynomial values to " << options.out
              << " ... ";
    std::ofstream out(options.out, std::ios_base::binary | std::ios_base::out);
    lagrange.write(out);
    out.close();

    std::cout << "DONE" << std::endl;
    return 0;
}

int main(int argc, char **argv)
{
    cli_options options;

    // Parse options
    try {
        options.parse(argc, argv);
    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        std::cout << std::endl;
        options.usage();
        return 1;
    }

    // Execute and handle errors
    try {
        return powersoftau_main(options);
    } catch (std::invalid_argument &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        std::cout << std::endl;
        return 1;
    }
}
