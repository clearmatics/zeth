// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/mpc/groth16/phase2.hpp"
#include "mpc_common.hpp"

#include <boost/program_options.hpp>
#include <fstream>

using namespace libzeth;
using pp = defaults::pp;
namespace po = boost::program_options;

namespace
{

// Usage:
//   $0 phase2-verify-transcript [<options>]
//       <challenge_0_file> <transcript_file> <final_challenge_file>
//
// Options:
//   --digest <file>   Confirm that a contribution with the given digest is
//                     included in the transcript.
class mpc_phase2_verify_transcript : public mpc_subcommand
{
private:
    std::string challenge_0_file;
    std::string transcript_file;
    std::string final_challenge_file;
    std::string digest;

public:
    mpc_phase2_verify_transcript()
        : mpc_subcommand(
              "phase2-verify-transcript",
              "Verify full transcript, check specific contribution")
        , challenge_0_file()
        , transcript_file()
        , final_challenge_file()
        , digest()
    {
    }

private:
    void initialize_suboptions(
        po::options_description &options,
        po::options_description &all_options,
        po::positional_options_description &pos) override
    {
        options.add_options()(
            "digest",
            po::value<std::string>(),
            "Check that transcript includes contribution digest");
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

    void parse_suboptions(const po::variables_map &vm) override
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
        digest = vm.count("digest") ? vm["digest"].as<std::string>() : "";
    }

    void subcommand_usage(const char *argv0) override
    {
        std::cout << "Usage:\n  " << argv0 << " " << subcommand_name
                  << " \\\n    <challenge_0_file> <transcript_file> "
                     "<final_challenge_file>\n\n";
    }

    int execute_subcommand(const global_options &options) override
    {
        if (options.verbose) {
            std::cout << "challenge_0: " << challenge_0_file << "\n"
                      << "transcript: " << transcript_file << "\n"
                      << "final_challenge: " << final_challenge_file
                      << std::endl;
        }

        // Load the initial challenge
        libff::enter_block("Load challenge_0 file");
        const srs_mpc_phase2_challenge<pp> challenge_0 =
            read_from_file<const srs_mpc_phase2_challenge<pp>>(
                challenge_0_file);
        libff::leave_block("Load challenge_0 file");

        // Simple sanity check on challenge.0. The initial transcript digest
        // should be based on the cs_hash for this MPC.
        {
            mpc_hash_t init_transcript_digest;
            mpc_compute_hash(
                init_transcript_digest,
                challenge_0.accumulator.cs_hash,
                sizeof(mpc_hash_t));
            if (0 != memcmp(
                         init_transcript_digest,
                         challenge_0.transcript_digest,
                         sizeof(mpc_hash_t))) {
                throw std::invalid_argument(
                    "transcript digest does not match starting challenge");
            }
        }

        bool check_for_contribution = false;

        // If required, load a contribution hash and set the
        // `check_for_contribution` flag.
        mpc_hash_t check_contribution_digest;
        if (!digest.empty()) {
            std::ifstream in(digest, std::ios_base::in);
            in.exceptions(
                std::ios_base::eofbit | std::ios_base::badbit |
                std::ios_base::failbit);
            if (!mpc_hash_read(check_contribution_digest, in)) {
                throw std::invalid_argument(
                    "could not parse contribution digest");
            }

            check_for_contribution = true;
        }

        // Verify transcript based on the initial challenge
        libff::enter_block("Verify transcript");
        libff::G1<pp> final_delta;
        mpc_hash_t final_transcript_digest{};
        {
            std::ifstream in(
                transcript_file, std::ios_base::binary | std::ios_base::in);
            bool transcript_valid = false;
            bool contribution_found = false;
            if (check_for_contribution) {
                transcript_valid = srs_mpc_phase2_verify_transcript<pp>(
                    challenge_0.transcript_digest,
                    challenge_0.accumulator.delta_g1,
                    check_contribution_digest,
                    in,
                    final_delta,
                    final_transcript_digest,
                    contribution_found);
            } else {
                contribution_found = true;
                transcript_valid = srs_mpc_phase2_verify_transcript<pp>(
                    challenge_0.transcript_digest,
                    challenge_0.accumulator.delta_g1,
                    in,
                    final_delta,
                    final_transcript_digest);
            }

            if (!transcript_valid) {
                std::cerr << "Transcript was invalid" << std::endl;
                return 1;
            }

            if (!contribution_found) {
                std::cerr << "Specified contribution digest was not found"
                          << std::endl;
                return 1;
            }
        }
        libff::leave_block("Verify transcript");

        // Load and check the final challenge
        libff::enter_block("Load phase2 output");
        const srs_mpc_phase2_challenge<pp> final_challenge =
            read_from_file<const srs_mpc_phase2_challenge<pp>>(
                final_challenge_file);
        libff::leave_block("Load phase2 output");

        libff::enter_block("Verify final output");
        if (0 != memcmp(
                     final_challenge.transcript_digest,
                     final_transcript_digest,
                     sizeof(mpc_hash_t))) {
            throw std::invalid_argument(
                "invalid transcript digest in final accumulator");
        }
        if (final_challenge.accumulator.delta_g1 != final_delta) {
            throw std::invalid_argument(
                "invalid delta_g1 in final accumulator");
        }
        if (!srs_mpc_phase2_update_is_consistent(
                challenge_0.accumulator, final_challenge.accumulator)) {
            throw std::invalid_argument("accumlators are inconsistent");
        }
        libff::leave_block("Verify final output");

        std::cout << "Transcript OK!" << std::endl;
        return 0;
    }
};

} // namespace

mpc_subcommand *mpc_phase2_verify_transcript_cmd =
    new mpc_phase2_verify_transcript();
