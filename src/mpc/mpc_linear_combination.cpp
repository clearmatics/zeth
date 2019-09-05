#include "circuit-wrapper.hpp"
#include "snarks/groth16/mpc_utils.hpp"
#include "snarks/groth16/powersoftau_utils.hpp"

#include <boost/program_options.hpp>
#include <fstream>
#include <functional>
#include <vector>

using namespace libzeth;
namespace po = boost::program_options;

namespace
{

using FieldT = libff::Fr<ppT>;
using HashTreeT = MiMC_mp_gadget<FieldT>;
using HashT = sha256_ethereum<FieldT>;

// Usage:
//     mpc linear-combination [<option>] <powersoftau file> <lagrange file>
//
// Options:
//     -h,--help        This message
//     --pot-degree     powersoftau degree (assumed equal to lagrange file)
//     --out <file>     Linear combination output (mpc-linear-combination.bin)
class cli_options
{
public:
    po::options_description desc;
    po::options_description all_desc;
    po::positional_options_description pos;

    std::string argv0;
    bool help;
    std::string powersoftau_file;
    std::string lagrange_file;
    size_t powersoftau_degree;
    std::string out;

    cli_options();
    void parse(const std::vector<std::string> &args);
    void usage() const;
};

cli_options::cli_options()
    : desc("Options")
    , all_desc("")
    , pos()
    , argv0("mpc linear-combination")
    , help(false)
    , powersoftau_file()
    , lagrange_file()
    , powersoftau_degree(0)
    , out()
{
    desc.add_options()("help,h", "This help")(
        "pot-degree",
        po::value<size_t>(),
        "powersoftau degree (assumed equal to lagrange file)")(
        "out,o",
        po::value<std::string>(),
        "linear combination output (mpc-linear-combination.bin)");
    all_desc.add(desc).add_options()(
        "powersoftau_file", po::value<std::string>(), "powersoftau file")(
        "lagrange_file", po::value<std::string>(), "lagrange file");
    pos.add("powersoftau_file", 1).add("lagrange_file", 1);
}

void cli_options::usage() const
{
    std::cout << "Usage:" << std::endl
              << "  " << argv0
              << " [<options>] <powersoftau file> <lagrange file>" << std::endl
              << std::endl
              << desc << std::endl;
}

void cli_options::parse(const std::vector<std::string> &args)
{
    po::variables_map vm;
    po::parsed_options parsed =
        po::command_line_parser(
            std::vector<std::string>(args.begin() + 1, args.end()))
            .options(all_desc)
            .positional(pos)
            .run();
    po::store(parsed, vm);

    argv0 = args[0];

    if (vm.count("help")) {
        help = true;
        return;
    }

    if (0 == vm.count("powersoftau_file")) {
        throw po::error("powersoftau_file not specified");
    }
    if (0 == vm.count("lagrange_file")) {
        throw po::error("lagrange_file not specified");
    }

    powersoftau_file = vm["powersoftau_file"].as<std::string>();
    lagrange_file = vm["lagrange_file"].as<std::string>();
    powersoftau_degree =
        vm.count("pot-degree") ? vm["pot-degree"].as<size_t>() : 0;
    out = vm.count("out") ? vm["out"].as<std::string>()
                          : "mpc-linear-combination.bin";
}

int zeth_mpc_linear_combination_main(const cli_options &options)
{
#if 1
    std::cout << "argv0: " << options.argv0 << std::endl;
    std::cout << "help: " << std::to_string(options.help) << std::endl;
    std::cout << "powersoftau_file: " << options.powersoftau_file << std::endl;
    std::cout << "lagrange_file: " << options.lagrange_file << std::endl;
    std::cout << "out: " << options.out << std::endl;
#endif

    // Load lagrange evaluations to determine n, then load powersoftau
    // TODO: Load just degree from lagrange data, then load the two
    // files in parallel.
    libff::enter_block("Load Lagrange data");
    libff::print_indent();
    std::cout << options.lagrange_file << std::endl;
    const srs_lagrange_evaluations<ppT> lagrange = [&options]() {
        std::ifstream in(
            options.lagrange_file, std::ios_base::binary | std::ios_base::in);
        return srs_lagrange_evaluations<ppT>::read(in);
    }();
    libff::leave_block("Load Lagrange data");

    libff::enter_block("Load powers of tau");
    libff::print_indent();
    std::cout << options.powersoftau_file << std::endl;
    const srs_powersoftau<ppT> pot = [&options, &lagrange]() {
        std::ifstream in(
            options.powersoftau_file,
            std::ios_base::binary | std::ios_base::in);
        const size_t pot_degree = options.powersoftau_degree
                                      ? options.powersoftau_degree
                                      : lagrange.degree;
        return powersoftau_load(in, pot_degree);
    }();
    libff::leave_block("Load powers of tau");

    // Compute circuit
    libff::enter_block("Generate QAP");
    libsnark::protoboard<FieldT> pb;
    joinsplit_gadget<
        FieldT,
        HashT,
        HashTreeT,
        ZETH_NUM_JS_INPUTS,
        ZETH_NUM_JS_OUTPUTS>
        js(pb);
    js.generate_r1cs_constraints();
    const libsnark::r1cs_constraint_system<FieldT> cs =
        pb.get_constraint_system();
    const libsnark::qap_instance<FieldT> qap =
        libsnark::r1cs_to_qap_instance_map(cs, true);
    libff::leave_block("Generate QAP");

    // Compute final step of linear combination
    if (qap.degree() != lagrange.degree) {
        throw std::invalid_argument(
            "Degree of qap " + std::to_string(qap.degree()) + " does not " +
            "match degree of lagrange evaluations. Regenerate with matching " +
            "degree.");
    }

    // Compute layer1 and write to a file
    const srs_mpc_layer_L1<ppT> lin_comb =
        mpc_compute_linearcombination<ppT>(pot, lagrange, qap);

    libff::enter_block("Writing linear combination file");
    libff::print_indent();
    std::cout << options.out << std::endl;
    {
        std::ofstream out(
            options.out, std::ios_base::binary | std::ios_base::out);
        lin_comb.write(out);
    }
    libff::leave_block("Writing linear combination file");

    return 0;
}

} // namespace

int zeth_mpc_linear_combination(const std::vector<std::string> &args)
{
    cli_options options;
    try {
        options.parse(args);
    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        std::cout << std::endl;
        options.usage();
        return 1;
    }

    // Execute and handle errors
    try {
        return zeth_mpc_linear_combination_main(options);
    } catch (std::invalid_argument &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        std::cout << std::endl;
        return 1;
    }
}
