#include "circuit-wrapper.hpp"
#include "snarks/groth16/mpc_utils.hpp"
#include "zeth.h"

#include <boost/program_options.hpp>
#include <fstream>

using namespace libzeth;
namespace po = boost::program_options;

namespace
{

using FieldT = libff::Fr<ppT>;
using HashTreeT = MiMC_mp_gadget<FieldT>;
using HashT = sha256_ethereum<FieldT>;

// Usage:
//     mpc new [<option>] <layer1_file>
//
// Options:
//     -h,--help           This message
//     --out <file>        Write layer2 to <file> (mpc-layer2.bin)
class cli_options
{
public:
    po::options_description desc;
    po::options_description all_desc;
    po::positional_options_description pos;

    std::string argv0;
    bool help;
    std::string layer1_file;
    std::string out;

    cli_options();
    void parse(const std::vector<std::string> &args);
    void usage() const;
};

cli_options::cli_options()
    : desc("Options")
    , all_desc("")
    , pos()
    , argv0("mpc dummy_layer2")
    , help(false)
    , layer1_file()
    , out()
{
    desc.add_options()("help,h", "This help")(
        "out,o",
        po::value<std::string>(),
        "layer2 output file (mpc-layer2.bin)");
    all_desc.add(desc).add_options()(
        "layer1_file", po::value<std::string>(), "layer1 file");
    pos.add("layer1_file", 1);
}

void cli_options::usage() const
{
    std::cout << "Usage:" << std::endl
              << "  " << argv0 << " [<options>] <layer1_file>" << std::endl
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

    if (0 == vm.count("layer1_file")) {
        throw po::error("layer1 file not specified");
    }
    layer1_file = vm["layer1_file"].as<std::string>();

    out = vm.count("out") ? vm["out"].as<std::string>() : "mpc-layer2.bin";
}

int zeth_mpc_new_main(const cli_options &options)
{
#if 1
    std::cout << "argv0: " << options.argv0 << std::endl;
    std::cout << "help: " << std::to_string(options.help) << std::endl;
    std::cout << "layer1_file: " << options.layer1_file << std::endl;
    std::cout << "out: " << options.out << std::endl;
#endif

    // Load the layer1 output
    libff::enter_block("reading layer1 data");
    srs_mpc_layer_L1<ppT> layer1 = [&options]() {
        std::ifstream in(options.layer1_file);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return srs_mpc_layer_L1<ppT>::read(in);
    }();
    libff::leave_block("reading layer1 data");

    // Generate the zeth circuit (to determine the number of inputs)
    const size_t num_inputs = []() {
        libsnark::protoboard<FieldT> pb;
        joinsplit_gadget<
            FieldT,
            HashT,
            HashTreeT,
            ZETH_NUM_JS_INPUTS,
            ZETH_NUM_JS_OUTPUTS>
            js(pb);
        const libsnark::r1cs_constraint_system<FieldT> cs =
            pb.get_constraint_system();
        return cs.num_inputs();
    }();

    // Generate the artifical delta
    const FieldT delta = FieldT::random_element();

    // Generate and save the dummy layer2 data
    const srs_mpc_layer_C2<ppT> layer2 =
        mpc_dummy_layer_C2<ppT>(layer1, delta, num_inputs);
    libff::enter_block("writing layer2 data");
    {
        std::ofstream out(options.out);
        layer2.write(out);
    }
    libff::leave_block("writing layer2 data");

    return 0;
}

} // namespace

int zeth_mpc_dummy_layer2(const std::vector<std::string> &args)
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
        return zeth_mpc_new_main(options);
    } catch (std::invalid_argument &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        std::cout << std::endl;
        return 1;
    }
}
