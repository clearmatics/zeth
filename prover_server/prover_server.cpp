// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/core/extended_proof.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/serialization/proto_utils.hpp"
#include "libzeth/serialization/r1cs_serialization.hpp"
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
using hash = libzeth::HashT<Field>;
using hash_tree = libzeth::HashTreeT<Field>;
using circuit_wrapper = libzeth::circuit_wrapper<
    hash,
    hash_tree,
    pp,
    snark,
    libzeth::ZETH_NUM_JS_INPUTS,
    libzeth::ZETH_NUM_JS_OUTPUTS,
    libzeth::ZETH_MERKLE_TREE_DEPTH>;

namespace proto = google::protobuf;
namespace po = boost::program_options;

static void prover_configuration_to_proto(
    zeth_proto::ProverConfiguration &prover_config_proto)
{
    prover_config_proto.set_zksnark(snark::name);
    libzeth::pairing_parameters_to_proto<pp>(
        *prover_config_proto.mutable_pairing_parameters());
}

static snark::keypair load_keypair(const boost::filesystem::path &keypair_file)
{
    std::ifstream in_s(
        keypair_file.c_str(), std::ios_base::in | std::ios_base::binary);
    in_s.exceptions(
        std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);
    return snark::keypair_read_bytes(in_s);
}

static void write_keypair(
    const typename snark::keypair &keypair,
    const boost::filesystem::path &keypair_file)
{
    std::ofstream out_s(
        keypair_file.c_str(), std::ios_base::out | std::ios_base::binary);
    snark::keypair_write_bytes(keypair, out_s);
}

static void write_constraint_system(
    const circuit_wrapper &prover, const boost::filesystem::path &r1cs_file)
{
    std::ofstream r1cs_stream(r1cs_file.c_str());
    libzeth::r1cs_write_json<pp>(prover.get_constraint_system(), r1cs_stream);
}

static void write_ext_proof_to_file(
    const libzeth::extended_proof<pp, snark> &ext_proof,
    boost::filesystem::path proof_path)
{
    std::ofstream os(proof_path.c_str());
    ext_proof.write_json(os);
}

/// The prover_server class inherits from the Prover service
/// defined in the proto files, and provides an implementation
/// of the service.
class prover_server final : public zeth_proto::Prover::Service
{
private:
    circuit_wrapper prover;

    // The keypair is the result of the setup. Store a copy internally.
    snark::keypair keypair;

    // Optional file to write proofs into (for debugging).
    boost::filesystem::path proof_output_file;

public:
    explicit prover_server(
        circuit_wrapper &prover,
        const snark::keypair &keypair,
        const boost::filesystem::path &proof_output_file)
        : prover(prover), keypair(keypair), proof_output_file(proof_output_file)
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
        zeth_proto::ExtendedProof *proof) override
    {
        std::cout << "[ACK] Received the request to generate a proof"
                  << std::endl;
        std::cout << "[DEBUG] Parse received message to compute proof..."
                  << std::endl;

        // Parse received message to feed to the prover
        try {
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
            libzeth::extended_proof<pp, snark> ext_proof = this->prover.prove(
                root,
                joinsplit_inputs,
                joinsplit_outputs,
                vpub_in,
                vpub_out,
                h_sig_in,
                phi_in,
                this->keypair.pk);

            std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
            ext_proof.write_json(std::cout);

            // Write a copy of the proof for debugging.
            if (!proof_output_file.empty()) {
                std::cout << "[DEBUG] Writing extended proof to "
                          << proof_output_file << "\n";
                write_ext_proof_to_file(ext_proof, proof_output_file);
            }

            std::cout << "[DEBUG] Preparing response..." << std::endl;
            api_handler::extended_proof_to_proto(ext_proof, proof);

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
        "Copyright (c) 2015-2020 Clearmatics Technologies Ltd";
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
    const boost::filesystem::path &proof_output_file)
{
    // Listen for incoming connections on 0.0.0.0:50051
    std::string server_address("0.0.0.0:50051");

    prover_server service(prover, keypair, proof_output_file);

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
    po::options_description options("");
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
        "proof-output,p",
        po::value<boost::filesystem::path>(),
        "(DEBUG) file to write generated proofs into");

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
    boost::filesystem::path proof_output_file;
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
        if (vm.count("proof-output")) {
            proof_output_file =
                vm["proof-output"].as<boost::filesystem::path>();
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
    std::cout << "[INFO] Init params" << std::endl;
    pp::init_public_params();

    // If the keypair file exists, load and use it, otherwise generate a new
    // keypair and write it to the file.
    circuit_wrapper prover;
    snark::keypair keypair = [&keypair_file, &prover]() {
        if (boost::filesystem::exists(keypair_file)) {
            std::cout << "[INFO] Loading keypair: " << keypair_file << "\n";
            return load_keypair(keypair_file);
        }

        std::cout << "[INFO] No keypair file " << keypair_file
                  << ". Generating.\n";
        const snark::keypair keypair = prover.generate_trusted_setup();
        std::cout << "[INFO] Writing new keypair to " << keypair_file << "\n";
        write_keypair(keypair, keypair_file);
        return keypair;
    }();

    // If a file is given, export the JSON representation of the constraint
    // system.
    if (!r1cs_file.empty()) {
        std::cout << "[INFO] Writing R1CS to " << r1cs_file << "\n";
        write_constraint_system(prover, r1cs_file);
    }

    std::cout << "[INFO] Setup successful, starting the server..." << std::endl;
    RunServer(prover, keypair, proof_output_file);
    return 0;
}
