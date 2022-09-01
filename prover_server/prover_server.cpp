// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libtool/tool_util.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/core/extended_proof.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/serialization/proto_utils.hpp"
#include "libzeth/serialization/r1cs_serialization.hpp"
#include "libzeth/serialization/r1cs_variable_assignment_serialization.hpp"
#include "libzeth/zeth_constants.hpp"
#include "zeth_config.h"

#include <boost/program_options.hpp>
#include <fstream>
#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <memory>
#include <stdio.h>
#include <string>
#include <zeth/api/prover.grpc.pb.h>

using pp = libzeth::defaults::pp;
using Field = libzeth::defaults::Field;
using snark = libzeth::defaults::snark;
using api_handler = libzeth::defaults::api_handler;
using circuit_wrapper = libzeth::JoinsplitCircuitT<pp, snark>;

namespace proto = google::protobuf;
namespace po = boost::program_options;

static void prover_configuration_to_proto(
    zeth_proto::ProverConfiguration &prover_config_proto)
{
    prover_config_proto.set_zksnark(snark::name);
    libzeth::pairing_parameters_to_proto<pp>(
        *prover_config_proto.mutable_pairing_parameters());
}

/// The prover_server class inherits from the Prover service
/// defined in the proto files, and provides an implementation
/// of the service.
class prover_server final : public zeth_proto::Prover::Service
{
private:
    circuit_wrapper &prover;

    // The keypair is the result of the setup. Store a copy internally.
    snark::keypair keypair;

    // Optional file to write proofs into (for debugging).
    boost::filesystem::path extproof_json_output_file;

    // Optional file to write proofs into (for debugging).
    boost::filesystem::path proof_output_file;

    // Optional file to write primary input data into (for debugging).
    boost::filesystem::path primary_output_file;

    // Optional file to write full assignments into (for debugging).
    boost::filesystem::path assignment_output_file;

public:
    explicit prover_server(
        circuit_wrapper &prover,
        const snark::keypair &keypair,
        const boost::filesystem::path &extproof_json_output_file,
        const boost::filesystem::path &proof_output_file,
        const boost::filesystem::path &primary_output_file,
        const boost::filesystem::path &assignment_output_file)
        : prover(prover)
        , keypair(keypair)
        , extproof_json_output_file(extproof_json_output_file)
        , proof_output_file(proof_output_file)
        , primary_output_file(primary_output_file)
        , assignment_output_file(assignment_output_file)
    {
    }

    grpc::Status GetConfiguration(
        grpc::ServerContext *,
        const proto::Empty *,
        zeth_proto::ProverConfiguration *response) override
    {
        std::cout << "[ACK] Received the request for configuration\n";
        prover_configuration_to_proto(*response);
        return grpc::Status::OK;
    }

    grpc::Status GetVerificationKey(
        grpc::ServerContext *,
        const proto::Empty *,
        zeth_proto::VerificationKey *response) override
    {
        std::cout << "[ACK] Received the request to get the verification key"
                  << std::endl;
        std::cout << "[DEBUG] Preparing verification key for response..."
                  << std::endl;
        try {
            api_handler::verification_key_to_proto(this->keypair.vk, response);
        } catch (const std::exception &e) {
            std::cout << "[ERROR] " << e.what() << std::endl;
            return grpc::Status(
                grpc::StatusCode::INVALID_ARGUMENT, grpc::string(e.what()));
        } catch (...) {
            std::cout << "[ERROR] In catch all" << std::endl;
            return grpc::Status(grpc::StatusCode::UNKNOWN, "");
        }

        return grpc::Status::OK;
    }

    grpc::Status Prove(
        grpc::ServerContext *,
        const zeth_proto::ProofInputs *proof_inputs,
        zeth_proto::ExtendedProofAndPublicData *proof_and_public_data) override
    {
        std::cout << "[ACK] Received the request to generate a proof"
                  << std::endl;
        std::cout << "[DEBUG] Parse received message to compute proof..."
                  << std::endl;

        // Parse received message to feed to the prover
        try {
            // TODO: Factor this into more maintainable smaller functions

            Field root = libzeth::base_field_element_from_hex<Field>(
                proof_inputs->mk_root());
            libzeth::bits64 vpub_in =
                libzeth::bits64::from_hex(proof_inputs->pub_in_value());
            libzeth::bits64 vpub_out =
                libzeth::bits64::from_hex(proof_inputs->pub_out_value());
            libzeth::bits256 h_sig_in =
                libzeth::bits256::from_hex(proof_inputs->h_sig());
            libzeth::bits256 phi_in =
                libzeth::bits256::from_hex(proof_inputs->phi());

            if (libzeth::ZETH_NUM_JS_INPUTS != proof_inputs->js_inputs_size()) {
                std::cout << "[INFO] Request with "
                          << proof_inputs->js_inputs_size()
                          << " inputs. Expecting "
                          << libzeth::ZETH_NUM_JS_INPUTS << "\n";
                throw std::invalid_argument("Invalid number of JS inputs");
            }
            if (libzeth::ZETH_NUM_JS_OUTPUTS !=
                proof_inputs->js_outputs_size()) {
                throw std::invalid_argument("Invalid number of JS outputs");
            }

            std::cout << "[DEBUG] Process all inputs of the JoinSplit"
                      << std::endl;
            std::array<
                libzeth::
                    joinsplit_input<Field, libzeth::ZETH_MERKLE_TREE_DEPTH>,
                libzeth::ZETH_NUM_JS_INPUTS>
                joinsplit_inputs;
            for (size_t i = 0; i < libzeth::ZETH_NUM_JS_INPUTS; i++) {
                printf(
                    "\r  input (%zu / %zu)\n", i, libzeth::ZETH_NUM_JS_INPUTS);
                const zeth_proto::JoinsplitInput &received_input =
                    proof_inputs->js_inputs(i);
                joinsplit_inputs[i] = libzeth::joinsplit_input_from_proto<
                    Field,
                    libzeth::ZETH_MERKLE_TREE_DEPTH>(received_input);
            }

            std::cout << "[DEBUG] Process all outputs of the JoinSplit"
                      << std::endl;
            std::array<libzeth::zeth_note, libzeth::ZETH_NUM_JS_OUTPUTS>
                joinsplit_outputs;
            for (size_t i = 0; i < libzeth::ZETH_NUM_JS_OUTPUTS; i++) {
                printf(
                    "\r  output (%zu / %zu)\n",
                    i,
                    libzeth::ZETH_NUM_JS_OUTPUTS);
                const zeth_proto::ZethNote &received_output =
                    proof_inputs->js_outputs(i);
                libzeth::zeth_note parsed_output =
                    libzeth::zeth_note_from_proto(received_output);
                joinsplit_outputs[i] = parsed_output;
            }

            std::cout << "[DEBUG] Data parsed successfully" << std::endl;
            std::cout << "[DEBUG] Generating the proof..." << std::endl;

            std::vector<Field> public_data;
            libzeth::extended_proof<pp, snark> ext_proof = this->prover.prove(
                root,
                joinsplit_inputs,
                joinsplit_outputs,
                vpub_in,
                vpub_out,
                h_sig_in,
                phi_in,
                this->keypair.pk,
                public_data);

            std::cout << "[DEBUG] Displaying extended proof and public data\n";
            ext_proof.write_json(std::cout);
            for (const Field &f : public_data) {
                std::cout << libzeth::base_field_element_to_hex(f) << "\n";
            }

            // Write a copy of the proof for debugging.
            if (!extproof_json_output_file.empty()) {
                std::cout << "[DEBUG] Writing extended proof (JSON) to "
                          << extproof_json_output_file << "\n";
                std::ofstream out_s(extproof_json_output_file.c_str());
                ext_proof.write_json(out_s);
            }
            if (!proof_output_file.empty()) {
                std::cout << "[DEBUG] Writing proof to " << proof_output_file
                          << "\n";
                std::ofstream out_s =
                    libtool::open_binary_output_file(proof_output_file.c_str());
                snark::proof_write_bytes(ext_proof.get_proof(), out_s);
            }
            if (!primary_output_file.empty()) {
                std::cout << "[DEBUG] Writing primary input to "
                          << primary_output_file << "\n";
                std::ofstream out_s = libtool::open_binary_output_file(
                    primary_output_file.c_str());
                libzeth::r1cs_variable_assignment_write_bytes(
                    ext_proof.get_primary_inputs(), out_s);
            }
            if (!assignment_output_file.empty()) {
                std::cout << "[DEBUG] WARNING! Writing assignment to "
                          << assignment_output_file << "\n";
                std::ofstream out_s = libtool::open_binary_output_file(
                    assignment_output_file.c_str());
                libzeth::r1cs_variable_assignment_write_bytes(
                    prover.get_last_assignment(), out_s);
            }

            std::cout << "[DEBUG] Preparing response..." << std::endl;
            api_handler::extended_proof_to_proto(
                ext_proof, proof_and_public_data->mutable_extended_proof());
            for (size_t i = 0; i < public_data.size(); ++i) {
                proof_and_public_data->add_public_data(
                    libzeth::base_field_element_to_hex(public_data[i]));
            }

        } catch (const std::exception &e) {
            std::cout << "[ERROR] " << e.what() << std::endl;
            return grpc::Status(
                grpc::StatusCode::INVALID_ARGUMENT, grpc::string(e.what()));
        } catch (...) {
            std::cout << "[ERROR] In catch all" << std::endl;
            return grpc::Status(grpc::StatusCode::UNKNOWN, "");
        }

        return grpc::Status::OK;
    }
};

std::string get_server_version()
{
    char buffer[100];
    int n;
    // Defined in the zethConfig file
    n = snprintf(
        buffer, 100, "Version %d.%d", ZETH_VERSION_MAJOR, ZETH_VERSION_MINOR);
    if (n < 0) {
        return "Version <Not specified>";
    }
    std::string version(buffer);
    return version;
}

void display_server_start_message()
{
    std::string copyright =
        "Copyright (c) 2015-2022 Clearmatics Technologies Ltd";
    std::string license = "SPDX-License-Identifier: LGPL-3.0+";
    std::string project =
        "R&D Department: PoC for Zerocash on Ethereum/Autonity";
    std::string version = get_server_version();
    std::string warning = "**WARNING:** This code is a research-quality proof "
                          "of concept, DO NOT use in production!";

    std::cout << "\n=====================================================\n";
    std::cout << copyright << "\n";
    std::cout << license << "\n";
    std::cout << project << "\n";
    std::cout << version << "\n";
    std::cout << warning << "\n";
    std::cout << "=====================================================\n"
              << std::endl;
}

static void RunServer(
    circuit_wrapper &prover,
    const typename snark::keypair &keypair,
    const boost::filesystem::path &extproof_json_output_file,
    const boost::filesystem::path &proof_output_file,
    const boost::filesystem::path &primary_output_file,
    const boost::filesystem::path &assignment_output_file)
{
    // Listen for incoming connections on 0.0.0.0:50051
    std::string server_address("0.0.0.0:50051");

    prover_server service(
        prover,
        keypair,
        extproof_json_output_file,
        proof_output_file,
        primary_output_file,
        assignment_output_file);

    grpc::ServerBuilder builder;

    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

    // Register "service" as the instance through which we'll communicate with
    // clients. In this case it corresponds to an *synchronous* service.
    builder.RegisterService(&service);

    // Finally assemble the server.
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::cout << "[INFO] Server listening on " << server_address << "\n";

    // Wait for the server to shutdown. Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    display_server_start_message();
    server->Wait();
}

int main(int argc, char **argv)
{
    // Options
    po::options_description options("Options");
    options.add_options()("help,h", "This help");
    options.add_options()(
        "keypair,k",
        po::value<boost::filesystem::path>(),
        "file to load keypair from. If it doesn't exist, a new keypair will be "
        "generated and written to this file. (default: "
        "~/zeth_setup/keypair.bin)");
    options.add_options()(
        "r1cs,r",
        po::value<boost::filesystem::path>(),
        "file in which to export the r1cs (in json format)");
    options.add_options()(
        "proving-key-output",
        po::value<boost::filesystem::path>(),
        "write proving key to file (if generated)");
    options.add_options()(
        "verification-key-output",
        po::value<boost::filesystem::path>(),
        "write verification key to file (if generated)");
    options.add_options()(
        "extproof-json-output",
        po::value<boost::filesystem::path>(),
        "(DEBUG) write generated extended proofs (JSON) to file");
    options.add_options()(
        "proof-output",
        po::value<boost::filesystem::path>(),
        "(DEBUG) write generated proofs to file");
    options.add_options()(
        "primary-output",
        po::value<boost::filesystem::path>(),
        "(DEBUG) write primary input to file");
    options.add_options()(
        "assignment-output",
        po::value<boost::filesystem::path>(),
        "(DEBUG) write full assignment to file (INSECURE!)");

    auto usage = [&]() {
        std::cout << "Usage:"
                  << "\n"
                  << "  " << argv[0] << " [<options>]\n"
                  << "\n";
        std::cout << options;
        std::cout << std::endl;
    };

    boost::filesystem::path keypair_file;
    boost::filesystem::path r1cs_file;
    boost::filesystem::path proving_key_output_file;
    boost::filesystem::path verification_key_output_file;
    boost::filesystem::path extproof_json_output_file;
    boost::filesystem::path proof_output_file;
    boost::filesystem::path primary_output_file;
    boost::filesystem::path assignment_output_file;
    try {
        po::variables_map vm;
        po::store(
            po::command_line_parser(argc, argv).options(options).run(), vm);
        if (vm.count("help")) {
            usage();
            return 0;
        }
        if (vm.count("keypair")) {
            keypair_file = vm["keypair"].as<boost::filesystem::path>();
        }
        if (vm.count("r1cs")) {
            r1cs_file = vm["r1cs"].as<boost::filesystem::path>();
        }
        if (vm.count("proving-key-output")) {
            proving_key_output_file =
                vm["proving-key-output"].as<boost::filesystem::path>();
        }
        if (vm.count("verification-key-output")) {
            verification_key_output_file =
                vm["verification-key-output"].as<boost::filesystem::path>();
        }
        if (vm.count("extproof-json-output")) {
            extproof_json_output_file =
                vm["extproof-json-output"].as<boost::filesystem::path>();
        }
        if (vm.count("proof-output")) {
            proof_output_file =
                vm["proof-output"].as<boost::filesystem::path>();
        }
        if (vm.count("primary-output")) {
            primary_output_file =
                vm["primary-output"].as<boost::filesystem::path>();
        }
        if (vm.count("assignment-output")) {
            assignment_output_file =
                vm["assignment-output"].as<boost::filesystem::path>();
        }
    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        usage();
        return 1;
    }

    // Default keypair_file if none given
    if (keypair_file.empty()) {
        boost::filesystem::path setup_dir =
            libzeth::get_path_to_setup_directory();
        if (!setup_dir.empty()) {
            boost::filesystem::create_directories(setup_dir);
        }
        keypair_file = setup_dir / "keypair.bin";
    }

    // Inititalize the curve parameters
    std::cout << "[INFO] Init params (" << libzeth::pp_name<pp>() << ")\n";
    pp::init_public_params();

    // If the keypair file exists, load and use it, otherwise generate a new
    // keypair and write it to the file.
    circuit_wrapper prover;
    snark::keypair keypair = [&keypair_file,
                              &proving_key_output_file,
                              &verification_key_output_file,
                              &prover]() {
        if (boost::filesystem::exists(keypair_file)) {
            std::cout << "[INFO] Loading keypair: " << keypair_file << "\n";

            snark::keypair keypair;
            std::ifstream in_s =
                libtool::open_binary_input_file(keypair_file.c_str());
            snark::keypair_read_bytes(keypair, in_s);
            return keypair;
        }

        std::cout << "[INFO] No keypair file " << keypair_file
                  << ". Generating.\n";
        const snark::keypair keypair = prover.generate_trusted_setup();

        if (!proving_key_output_file.empty()) {
            std::cout << "[DEBUG] Writing separate proving key to "
                      << proving_key_output_file << "\n";
            std::ofstream out_s = libtool::open_binary_output_file(
                proving_key_output_file.c_str());
            snark::proving_key_write_bytes(keypair.pk, out_s);
        }
        if (!verification_key_output_file.empty()) {
            std::cout << "[DEBUG] Writing separate verification key to "
                      << verification_key_output_file << "\n";
            std::ofstream out_s = libtool::open_binary_output_file(
                verification_key_output_file.c_str());
            snark::verification_key_write_bytes(keypair.vk, out_s);
        }

        // Write the keypair last. If something above fails, this same
        // code-path will be executed again on the next invocation.
        std::cout << "[INFO] Writing new keypair to " << keypair_file << "\n";
        std::ofstream out_s =
            libtool::open_binary_output_file(keypair_file.c_str());
        snark::keypair_write_bytes(keypair, out_s);

        return keypair;
    }();

    // If a file is given, export the JSON representation of the constraint
    // system.
    if (!r1cs_file.empty()) {
        std::cout << "[INFO] Writing R1CS to " << r1cs_file << "\n";
        std::ofstream r1cs_stream(r1cs_file.c_str());
        libzeth::r1cs_write_json(prover.get_constraint_system(), r1cs_stream);
    }

    std::cout << "[INFO] Setup successful, starting the server..." << std::endl;
    RunServer(
        prover,
        keypair,
        extproof_json_output_file,
        proof_output_file,
        primary_output_file,
        assignment_output_file);
    return 0;
}
