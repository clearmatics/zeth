#include "mpc_common.hpp"
#include "snarks/groth16/mpc_phase2.hpp"

#include <boost/program_options.hpp>
#include <fstream>

using namespace libzeth;
namespace po = boost::program_options;

namespace
{

// Usage:
//   $0 phase2-verify-transcript
//       <challenge_0_file> <transcript_file> <final_challenge_file>
class mpc_phase2_verify_transcript : public subcommand
{
private:
    std::string challenge_0_file;
    std::string transcript_file;
    std::string final_challenge_file;

public:
    mpc_phase2_verify_transcript()
        : subcommand("phase2-verify-transcript")
        , challenge_0_file()
        , transcript_file()
        , final_challenge_file()
    {
    }

private:
    void initialize_suboptions(
        boost::program_options::options_description &options,
        boost::program_options::options_description &all_options,
        boost::program_options::positional_options_description &pos) override
    {
        all_options.add(options).add_options()(
            "challenge_0_file", po::value<std::string>(), "challenge file")(
            "transcript_file", po::value<std::string>(), "transcript file")(
            "final_challenge_file",
            po::value<std::string>(),
            "final challenge file");
        pos.add("challenge_0_file", 1)
            .add("transcript_file", 1)
            .add("final_challenge_file", 1);
    }

    void parse_suboptions(
        const boost::program_options::variables_map &vm) override
    {
        if (0 == vm.count("challenge_0_file")) {
            throw po::error("challenge_0_file not specified");
        }
        if (0 == vm.count("transcript_file")) {
            throw po::error("transcript_file not specified");
        }
        if (0 == vm.count("final_challenge_file")) {
            throw po::error("final_challenge_file not specified");
        }
        challenge_0_file = vm["challenge_0_file"].as<std::string>();
        transcript_file = vm["transcript_file"].as<std::string>();
        final_challenge_file = vm["final_challenge_file"].as<std::string>();
    }

    void subcommand_usage() override
    {
        std::cout << "Usage:\n  " << subcommand_name
                  << " \\\n    <challenge_0_file> <transcript_file> "
                     "<final_challenge_file>\n\n";
    }

    int execute_subcommand() override
    {
        if (verbose) {
            std::cout << "challenge_0: " << challenge_0_file << "\n"
                      << "transcript: " << transcript_file << "\n"
                      << "final_challenge: " << final_challenge_file
                      << std::endl;
        }

        // Load the initial challenge
        libff::enter_block("Load challenge_0 file");
        const srs_mpc_phase2_challenge<ppT> challenge_0 = [&]() {
            std::ifstream in(
                challenge_0_file, std::ios_base::binary | std::ios_base::in);
            in.exceptions(
                std::ios_base::eofbit | std::ios_base::badbit |
                std::ios_base::failbit);
            return srs_mpc_phase2_challenge<ppT>::read(in);
        }();
        libff::leave_block("Load challenge_0 file");

        // Verify transcript based on the initial challenge
        libff::enter_block("Verify transcript");
        libff::G1<ppT> final_delta;
        srs_mpc_hash_t final_transcript_digest{};
        {
            std::ifstream in(
                transcript_file, std::ios_base::binary | std::ios_base::in);
            // in.exceptions(
            //     std::ios_base::eofbit | std::ios_base::badbit |
            //     std::ios_base::failbit);
            const bool transcript_valid = srs_mpc_phase2_verify_transcript<ppT>(
                challenge_0.transcript_digest,
                challenge_0.accumulator.delta_g1,
                in,
                final_delta,
                final_transcript_digest);
            if (!transcript_valid) {
                return false;
            }
        }
        libff::leave_block("Verify transcript");

        // Load and check the final challenge
        libff::enter_block("Load phase2 output");
        const srs_mpc_phase2_challenge<ppT> final_challenge = [&]() {
            std::ifstream in(
                final_challenge_file,
                std::ios_base::binary | std::ios_base::in);
            in.exceptions(
                std::ios_base::eofbit | std::ios_base::badbit |
                std::ios_base::failbit);
            return srs_mpc_phase2_challenge<ppT>::read(in);
        }();
        libff::leave_block("Load phase2 output");

        libff::enter_block("Verify final output");
        if (0 != memcmp(
                     final_challenge.transcript_digest,
                     final_transcript_digest,
                     sizeof(srs_mpc_hash_t))) {
            throw std::invalid_argument(
                "invalid transcript digest in final accumlator");
        }
        if (final_challenge.accumulator.delta_g1 != final_delta) {
            throw std::invalid_argument("invalid delta_g1 in final accumlator");
        }
        if (!srs_mpc_phase2_update_is_consistent(
                challenge_0.accumulator, final_challenge.accumulator)) {
            throw std::invalid_argument("accumlators are inconsistent");
        }
        libff::leave_block("Verify final output");

        return 0;
    }
};

} // namespace

subcommand *mpc_phase2_verify_transcript_cmd =
    new mpc_phase2_verify_transcript();
