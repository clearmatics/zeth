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
//   $0 phase2-contribute [<options>] <challenge_file> <response_file>
//
// Options:
//   --digest <file>     Write contribution hash to file
//   --skip-user-input   Use only system randomness
class mpc_phase2_contribute : public mpc_subcommand
{
private:
    std::string challenge_file;
    std::string out_file;
    std::string digest_file;
    bool skip_user_input;

public:
    mpc_phase2_contribute()
        : mpc_subcommand(
              "phase2-contribute",
              "Create response (MPC contribution) from challenge")
        , challenge_file()
        , out_file()
        , digest_file()
        , skip_user_input(false)
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
            "Write contribution digest to file")(
            "skip-user-input", "Use only system randomness");
        all_options.add(options).add_options()(
            "challenge_file", po::value<std::string>(), "challenge file")(
            "response_file", po::value<std::string>(), "response output file");
        pos.add("challenge_file", 1).add("response_file", 1);
    }

    void parse_suboptions(const po::variables_map &vm) override
    {
        if (0 == vm.count("challenge_file")) {
            throw po::error("challenge_file not specified");
        }
        if (0 == vm.count("response_file")) {
            throw po::error("response_file not specified");
        }
        challenge_file = vm["challenge_file"].as<std::string>();
        out_file = vm["response_file"].as<std::string>();
        digest_file = vm.count("digest") ? vm["digest"].as<std::string>() : "";
        skip_user_input = (bool)vm.count("skip-user-input");
    }

    void subcommand_usage(const char *argv0) override
    {
        std::cout << "Usage:\n  " << argv0 << " " << subcommand_name
                  << " [<options>] <challenge_file> <response_file>\n\n";
    }

    int execute_subcommand(const global_options &options) override
    {
        if (options.verbose) {
            std::cout << "challenge_file: " << challenge_file << "\n";
            std::cout << "out_file: " << out_file << std::endl;
            std::cout << "digest: " << digest_file << std::endl;
            std::cout << "skip_user_input: " << skip_user_input << std::endl;
        }

        libff::enter_block("Load challenge file");
        srs_mpc_phase2_challenge<pp> challenge =
            read_from_file<srs_mpc_phase2_challenge<pp>>(challenge_file);
        libff::leave_block("Load challenge file");

        libff::enter_block("Computing randomness");
        libff::Fr<pp> contribution = get_randomness();
        libff::leave_block("Computing randomness");

        libff::enter_block("Computing response");
        const srs_mpc_phase2_response<pp> response =
            srs_mpc_phase2_compute_response<pp>(challenge, contribution);
        libff::leave_block("Computing response");

        libff::enter_block("Writing response");
        libff::print_indent();
        std::cout << out_file << std::endl;
        {
            std::ofstream out(out_file);
            response.write(out);
        }
        libff::leave_block("Writing response");

        mpc_hash_t contrib_digest;
        response.publickey.compute_digest(contrib_digest);
        std::cout << "Digest of the contribution was:\n";
        mpc_hash_write(contrib_digest, std::cout);

        if (!digest_file.empty()) {
            std::ofstream out(digest_file);
            mpc_hash_write(contrib_digest, out);
            std::cout << "Digest written to: " << digest_file << std::endl;
        }

        return 0;
    }

    libff::Fr<pp> get_randomness() const
    {
        using random_word = std::random_device::result_type;

        std::random_device rd;
        mpc_hash_ostream hs;
        uint64_t buf[4];
        // The computation below looks (to some compilers) like an attempt to
        // compute the number of elements in the array 'buf', and generates a
        // warning.  In fact, we want to know how many `std::random_device`
        // elements to generate, so the calculation is correct.  The cast to
        // `size_t` prevents the compile warning.
        const size_t buf_size_in_words =
            sizeof(buf) / (size_t)sizeof(random_word);

        // 1024 bytes of system randomness,
        for (size_t i = 0; i < 1024 / sizeof(buf); ++i) {
            random_word *words = (random_word *)&buf;
            for (size_t j = 0; j < buf_size_in_words; ++j) {
                words[j] = rd();
            }
            hs.write((const char *)&buf, sizeof(buf));
        }

        if (!skip_user_input) {
            std::cout << "Enter some random text and press [ENTER] ..."
                      << std::endl;
            std::string user_input;
            std::getline(std::cin, user_input);
            hs << user_input;
        }

        mpc_hash_t randomness_digest;
        hs.get_hash(randomness_digest);

        libff::Fr<pp> random_fp;
        srs_mpc_digest_to_fp(randomness_digest, random_fp);
        return random_fp;
    }
};

} // namespace

mpc_subcommand *mpc_phase2_contribute_cmd = new mpc_phase2_contribute();
