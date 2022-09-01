// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/mpc/groth16/phase2.hpp"
#include "mpc_common.hpp"

using namespace libzeth;
using pp = defaults::pp;
namespace po = boost::program_options;

namespace
{

// Usage:
//   $0 phase2-verify-contribution [<options>] <challenge_file> <response_file>
//
// Options:
//   --transcript <file>     Append contribution, if it is valid
//   --new-challenge <file>  Write new challenge, if contribution is valid
class mpc_phase2_verify_contribution : public mpc_subcommand
{
private:
    std::string challenge_file;
    std::string response_file;
    std::string transcript_file;
    std::string new_challenge_file;

public:
    mpc_phase2_verify_contribution()
        : mpc_subcommand(
              "mpc_phase2_verify_contribution",
              "Verify contribution and optionally output next challenge")
        , challenge_file()
        , response_file()
        , transcript_file()
        , new_challenge_file()
    {
    }

private:
    void initialize_suboptions(
        po::options_description &options,
        po::options_description &all_options,
        po::positional_options_description &pos) override
    {
        options.add_options()(
            "transcript",
            po::value<std::string>(),
            "Append contribution, if it is valid")(
            "new-challenge",
            po::value<std::string>(),
            "Write new challenge, if contribution is valid");
        all_options.add(options).add_options()(
            "challenge_file", po::value<std::string>(), "challenge file")(
            "response_file", po::value<std::string>(), "response file");
        pos.add("challenge_file", 1).add("response_file", 1);
    }

    void parse_suboptions(const po::variables_map &vm) override
    {
        if (!vm.count("challenge_file")) {
            throw po::error("challenge_file not specified");
        }
        if (!vm.count("response_file")) {
            throw po::error("response_file not specified");
        }
        challenge_file = vm["challenge_file"].as<std::string>();
        response_file = vm["response_file"].as<std::string>();
        transcript_file =
            vm.count("transcript") ? vm["transcript"].as<std::string>() : "";
        new_challenge_file = vm.count("new-challenge")
                                 ? vm["new-challenge"].as<std::string>()
                                 : "";
    }

    void subcommand_usage(const char *argv0) override
    {
        std::cout << "Usage:\n  " << argv0 << " " << subcommand_name
                  << " [<options>] <challenge_file> <response_file>\n\n";
    }

    int execute_subcommand(const global_options &options) override
    {
        if (options.verbose) {
            std::cout << "challenge: " << challenge_file << "\n"
                      << "response: " << response_file << "\n"
                      << "transcript: " << transcript_file << "\n"
                      << "new_challenge: " << new_challenge_file << std::endl;
        }

        libff::enter_block("Load challenge file");
        srs_mpc_phase2_challenge<pp> challenge =
            read_from_file<srs_mpc_phase2_challenge<pp>>(challenge_file);
        libff::leave_block("Load challenge file");

        libff::enter_block("Load response file");
        srs_mpc_phase2_response<pp> response =
            read_from_file<srs_mpc_phase2_response<pp>>(response_file);
        libff::leave_block("Load response file");

        libff::enter_block("Verifying response");
        const bool response_is_valid =
            srs_mpc_phase2_verify_response(challenge, response);
        libff::leave_block("Verifying response");
        if (!response_is_valid) {
            std::cerr << "Response is invalid" << std::endl;
            return 1;
        }

        // TODO: Backup the transcript file before writing a new version?

        // If a transcript file has been specified, append this contribution
        if (!transcript_file.empty()) {
            libff::enter_block("appending contribution to transcript");
            std::ofstream out(
                transcript_file,
                std::ios_base::binary | std::ios_base::out |
                    std::ios_base::app);
            response.publickey.write(out);
            libff::leave_block("appending contribution to transcript");
        }

        // If a new-challenge file has been specified, create and write a new
        // challenge.
        if (!new_challenge_file.empty()) {
            libff::enter_block("computing and writing new challenge");
            srs_mpc_phase2_challenge<pp> new_challenge =
                srs_mpc_phase2_compute_challenge(std::move(response));
            std::ofstream out(
                new_challenge_file, std::ios_base::binary | std::ios_base::out);
            new_challenge.write(out);
            libff::leave_block("computing and writing new challenge");
        }

        return 0;
    }
};

} // namespace

mpc_subcommand *mpc_phase2_verify_contribution_cmd =
    new mpc_phase2_verify_contribution();
