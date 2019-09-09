#include "mpc_common.hpp"
#include "snarks/groth16/mpc_phase2.hpp"

using namespace libzeth;
namespace po = boost::program_options;

namespace
{

// Usage:
//   $0 phase2-contribute [<options>] <challenge_file>
//
// Options:
//   --out <file>      Response output file (mpc-response.bin)
//   --digest <file>   Write contribution hash to file.
class mpc_phase2_contribute : public subcommand
{
private:
    std::string challenge_file;
    std::string out_file;
    std::string digest;

public:
    mpc_phase2_contribute()
        : subcommand("phase2-contribute")
        , challenge_file()
        , out_file()
        , digest()
    {
    }

private:
    void initialize_suboptions(
        boost::program_options::options_description &options,
        boost::program_options::options_description &all_options,
        boost::program_options::positional_options_description &pos) override
    {
        options.add_options()(
            "out,o",
            po::value<std::string>(),
            "Reponse output file (mpc-response.bin)")(
            "digest",
            po::value<std::string>(),
            "Write contribution digest to file");
        all_options.add(options).add_options()(
            "challenge_file", po::value<std::string>(), "challenge file");
        pos.add("challenge_file", 1);
    }

    void parse_suboptions(
        const boost::program_options::variables_map &vm) override
    {
        if (0 == vm.count("challenge_file")) {
            throw po::error("challenge_file not specified");
        }
        challenge_file = vm["challenge_file"].as<std::string>();
        out_file = vm.count("out") ? vm["out"].as<std::string>()
                                   : trusted_setup_file("mpc-response.bin");
        digest = vm.count("digest") ? vm["digest"].as<std::string>() : "";
    }

    void subcommand_usage() override
    {
        std::cout << "Usage:\n  " << subcommand_name
                  << " [<options>] <challenge_file>\n\n";
    }

    int execute_subcommand() override
    {
        if (verbose) {
            std::cout << "challenge_file: " << challenge_file << "\n";
            std::cout << "out_file: " << out_file << std::endl;
            std::cout << "digest: " << digest << std::endl;
        }

        libff::enter_block("Load challenge file");
        srs_mpc_phase2_challenge<ppT> challenge = [&]() {
            std::ifstream in(
                challenge_file, std::ios_base::binary | std::ios_base::in);
            return srs_mpc_phase2_challenge<ppT>::read(in);
        }();
        libff::leave_block("Load challenge file");

        libff::enter_block("Computing randomness");
        // TODO: determine strategy for this.
        libff::Fr<ppT> contribution = libff::Fr<ppT>::random_element();
        libff::leave_block("Computing randomness");

        libff::enter_block("Computing response");
        const srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response<ppT>(challenge, contribution);
        libff::leave_block("Computing response");

        libff::enter_block("Writing response");
        libff::print_indent();
        std::cout << out_file << std::endl;
        {
            std::ofstream out(out_file);
            response.write(out);
        }
        libff::leave_block("Writing response");

        srs_mpc_hash_t contr_digest;
        response.publickey.compute_digest(contr_digest);
        std::cout << "Digest of the contribution was:\n";
        srs_mpc_hash_write(contr_digest, std::cout);

        if (!digest.empty()) {
            std::ofstream out(digest);
            srs_mpc_hash_write(contr_digest, out);
            std::cout << "Digest written to: " << digest << std::endl;
        }

        return 0;
    }
};

} // namespace

subcommand *mpc_phase2_contribute_cmd = new mpc_phase2_contribute();
