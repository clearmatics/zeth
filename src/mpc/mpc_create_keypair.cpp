#include "circuit-wrapper.hpp"
#include "snarks/groth16/mpc_utils.hpp"
#include "snarks/groth16/powersoftau_utils.hpp"

#include <boost/program_options.hpp>
#include <vector>

using namespace libzeth;
namespace po = boost::program_options;

namespace
{

using FieldT = libff::Fr<ppT>;
using HashTreeT = MiMC_mp_gadget<FieldT>;
using HashT = sha256_ethereum<FieldT>;

// Usage:
//  mpc create-keypair [<option>]
//      <powersoftau_file>
//      <linear_combination_file>
//      <phase2_file>
//
// Options:
//  -h,--help           This message
//  --pot-degree        powersoftau degree (assumed to match linear comb)
//  --out <file>        Write key-pair to <file> (mpc-keypair.bin)
class cli_options
{
public:
    po::options_description desc;
    po::options_description all_desc;
    po::positional_options_description pos;

    std::string argv0;
    bool help;
    std::string powersoftau_file;
    std::string lin_comb_file;
    std::string phase2_file;
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
    , argv0("mpc create-keypair")
    , help(false)
    , powersoftau_file()
    , lin_comb_file()
    , phase2_file()
    , powersoftau_degree(0)
    , out()
{
    desc.add_options()("help,h", "This help")(
        "pot-degree",
        po::value<size_t>(),
        "powersoftau degree (assumed to match linear comb)")(
        "out,o",
        po::value<std::string>(),
        "Write key-pair to file (mpc-keypair.bin)");
    all_desc.add(desc).add_options()(
        "powersoftau_file", po::value<std::string>(), "powersoftau file")(
        "linear_combination_file",
        po::value<std::string>(),
        "linear combination file")(
        "phase2_file", po::value<std::string>(), "phase2 final challenge file");
    pos.add("powersoftau_file", 1)
        .add("linear_combination_file", 1)
        .add("phase2_file", 1);
}

void cli_options::usage() const
{
    std::cout << "Usage:\n"
              << "  " << argv0 << " [<options>]  \\\n"
              << "        <powersoftau_file> <linear_combination_file> "
                 "<phase2_file>\n\n"
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
    if (0 == vm.count("linear_combination_file")) {
        throw po::error("linear_combination_file not specified");
    }
    if (0 == vm.count("phase2_file")) {
        throw po::error("phase2_file not specified");
    }

    powersoftau_file = vm["powersoftau_file"].as<std::string>();
    lin_comb_file = vm["linear_combination_file"].as<std::string>();
    phase2_file = vm["phase2_file"].as<std::string>();
    powersoftau_degree =
        vm.count("pot-degree") ? vm["pot-degree"].as<size_t>() : 0;
    out = vm.count("out") ? vm["out"].as<std::string>() : "mpc-keypair.bin";
}

int zeth_mpc_create_keypair_main(const cli_options &options)
{
    // Load all data
    // TODO: Load just degree from lin_comb data, then load everything
    // in parallel.
    libff::enter_block("Load linear combination data");
    libff::print_indent();
    std::cout << options.lin_comb_file << std::endl;
    srs_mpc_layer_L1<ppT> lin_comb = [&options]() {
        std::ifstream in(
            options.lin_comb_file, std::ios_base::binary | std::ios_base::in);
        return srs_mpc_layer_L1<ppT>::read(in);
    }();
    libff::leave_block("Load linear combination data");

    libff::enter_block("Load powers of tau");
    libff::print_indent();
    std::cout << options.powersoftau_file << std::endl;
    srs_powersoftau<ppT> pot = [&options, &lin_comb]() {
        std::ifstream in(
            options.powersoftau_file,
            std::ios_base::binary | std::ios_base::in);
        const size_t pot_degree = options.powersoftau_degree
                                      ? options.powersoftau_degree
                                      : lin_comb.degree();
        return powersoftau_load(in, pot_degree);
    }();
    libff::leave_block("Load powers of tau");

    libff::enter_block("Load phase2 data");
    if (!libff::inhibit_profiling_info) {
        libff::print_indent();
        std::cout << options.phase2_file << "\n";
    }
    srs_mpc_layer_C2<ppT> phase2 = [&options]() {
        std::ifstream in(
            options.phase2_file, std::ios_base::binary | std::ios_base::in);
        return srs_mpc_layer_C2<ppT>::read(in);
    }();
    libff::leave_block("Load phase2 data");

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
    libsnark::r1cs_constraint_system<FieldT> cs = pb.get_constraint_system();
    const libsnark::qap_instance<FieldT> qap =
        libsnark::r1cs_to_qap_instance_map(cs, true);
    libff::leave_block("Generate QAP");

    libsnark::r1cs_gg_ppzksnark_keypair<ppT> keypair = mpc_create_key_pair(
        std::move(pot),
        std::move(lin_comb),
        std::move(phase2),
        std::move(cs),
        qap);

    // Write keypair to a file
    libff::enter_block("Writing keypair file");
    if (!libff::inhibit_profiling_info) {
        libff::print_indent();
        std::cout << options.out << std::endl;
    }
    {
        std::ofstream out(
            options.out, std::ios_base::binary | std::ios_base::out);
        mpc_write_keypair(out, keypair);
    }
    libff::leave_block("Writing keypair file");

    return 0;
}

} // namespace

int zeth_mpc_create_keypair(const std::vector<std::string> &args)
{
    cli_options options;
    try {
        options.parse(args);
    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        options.usage();
        return 1;
    }

    // Execute and handle errors
    try {
        return zeth_mpc_create_keypair_main(options);
    } catch (std::invalid_argument &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        return 1;
    }
}
