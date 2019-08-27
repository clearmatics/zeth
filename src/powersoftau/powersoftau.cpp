/// Small utility to verify powersoftau output and to compute the
/// evaluation of Lagrange polynomials at tau.

#include "snarks/groth16/powersoftau_utils.hpp"

#include <boost/program_options.hpp>
#include <fstream>

using namespace libzeth;
namespace po = boost::program_options;
using ppT = libff::default_ec_pp;

// -----------------------------------------------------------------------------
// cli_options
// -----------------------------------------------------------------------------

// Usage:
//     powersoftau [<options>] <powersoftau file> <degree>
//
// Options:
//     -h,--help              This message
//     -v,--verbose           Verbose
//     --verify               Verify only
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

    std::string argv0;
    bool help;
    std::string powersoftau_file;
    size_t degree;
    bool verbose;
    bool verify;
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
    , argv0("powersoftau")
    , help(false)
    , powersoftau_file()
    , degree(0)
    , verbose(false)
    , verify(false)
    , out()
    , lagrange_degree(0)
{
    desc.add_options()("help,h", "This help")("verbose,v", "Verbose output")(
        "verify",
        "Verify only")("out,o", po::value<std::string>(), "Output file")(
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
              << "  " << argv0 << " [<options>] <powersoftau file> <degree>"
              << std::endl
              << std::endl
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

    argv0 = argv[0];

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
    verify = vm.count("verify");
    degree = vm["degree"].as<size_t>();
    lagrange_degree = vm.count("lagrange-degree")
                          ? vm["lagrange-degree"].as<size_t>()
                          : degree;
    out = vm.count("out") ? vm["out"].as<std::string>()
                          : "lagrange-" + std::to_string(lagrange_degree);
    dummy = vm.count("dummy");

    if (dummy && verify) {
        throw po::error("specify at most one of --dummy and --verify");
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
        std::cout << " argv0: " << options.argv0 << "\n";
        std::cout << " help: " << std::to_string(options.help) << "\n";
        std::cout << " powersoftau_file: " << options.powersoftau_file << "\n";
        std::cout << " degree: " << std::to_string(options.degree) << "\n";
        std::cout << " verbose: " << std::to_string(options.verbose) << "\n";
        std::cout << " verify: " << std::to_string(options.verify) << "\n";
        std::cout << " out: " << options.out << "\n";
        std::cout << " lagrange_degree: "
                  << std::to_string(options.lagrange_degree) << std::endl;
    }

    ppT::init_public_params();
    if (!options.verbose) {
        libff::inhibit_profiling_counters = true;
        libff::inhibit_profiling_info = true;
    }

    // If --dummy options was given, create a powersoftau struct from
    // local randomness, write it out and return.
    if (options.dummy) {
        const srs_powersoftau<ppT> dummy =
            dummy_powersoftau<ppT>(options.degree);
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
    const srs_powersoftau<ppT> powersoftau =
        powersoftau_load(in, options.degree);
    in.close();

    // If --verify was given, run the verification and stop.
    if (options.verify) {
        if (!powersoftau_validate(powersoftau, options.degree)) {
            std::cerr << "Error validating powersoftau file" << std::endl;
            return 1;
        }

        std::cout << "powersoftau file is valid" << std::endl;
        return 0;
    }

    srs_lagrange_evaluations<ppT> lagrange =
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
