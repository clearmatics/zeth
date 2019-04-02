#include <iostream>
#include <memory>
#include <string>
#include <stdio.h>

#include <grpc/grpc.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <grpcpp/security/server_credentials.h>

// Necessary header to parse the data
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Include zeth headers
#include "zeth.h"
#include "libsnark_helpers/libsnark_helpers.hpp"
#include "circuits/sha256/sha256_ethereum.hpp"
#include "zethConfig.h"

#include "util.hpp"

// Include the file generated by gRPC
#include "prover.grpc.pb.h"

//Include circuit wrapper that makes use of the conditioned imported files above
#include "circuit-wrapper.hpp"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;

// Use the Prover service defined in the proto file
using proverpkg::Prover;

// Use the messages defined in the proto file
using proverpkg::EmptyMessage;
using proverpkg::PackedDigest;
using proverpkg::ProofInputs;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;
typedef sha256_ethereum<FieldT> HashT;

class ProverImpl final : public Prover::Service {
private:
  libzeth::CircuitWrapper<ZETH_NUM_JS_INPUTS, ZETH_NUM_JS_OUTPUTS> prover;
  keyPairT<ppT> keypair; // Result of the setup

public:
  explicit ProverImpl(
    libzeth::CircuitWrapper<ZETH_NUM_JS_INPUTS, ZETH_NUM_JS_OUTPUTS>& prover,
    keyPairT<ppT>& keypair
  ) : prover(prover), keypair(keypair) {}

  Status GetVerificationKey(
    ServerContext* context,
    const EmptyMessage* request,
    VerificationKey* response
  ) override {
    std::cout << "[ACK] Received the request to get the verification key" << std::endl;
    std::cout << "[DEBUG] Preparing verification key for response..." << std::endl;
    try {
      PrepareVerifyingKeyResponse(this->keypair.vk, response);
    } catch (const std::exception& e) {
      std::cout << "[ERROR] " << e.what() << std::endl;
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, grpc::string(e.what()));
    } catch (...) {
      std::cout << "[ERROR] In catch all" << std::endl;
      return ::grpc::Status(::grpc::StatusCode::UNKNOWN, "");
    }

    return Status::OK;
  }

  Status Prove(
    ServerContext* context,
    const ProofInputs* proofInputs,
    ExtendedProof* proof
  ) override {
    std::cout << "[ACK] Received the request to generate a proof" << std::endl;
    std::cout << "[DEBUG] Parse received message to compute proof..." << std::endl;

    // Parse received message to feed to the prover
    try {
      libzeth::bits256 root_bits = libzeth::hexadecimal_digest_to_bits256(proofInputs->root());
      libzeth::bits64 vpub_in = libzeth::hexadecimal_value_to_bits64(proofInputs->inpubvalue());
      libzeth::bits64 vpub_out = libzeth::hexadecimal_value_to_bits64(proofInputs->outpubvalue());

      if (ZETH_NUM_JS_INPUTS != proofInputs->jsinputs_size()) {
        throw std::invalid_argument("Invalid number of JS inputs");
      }
      if (ZETH_NUM_JS_OUTPUTS != proofInputs->jsoutputs_size()) {
        throw std::invalid_argument("Invalid number of JS outputs");
      }

      std::cout << "[DEBUG] Process every inputs of the JoinSplit" << std::endl;
      std::array<libzeth::JSInput, ZETH_NUM_JS_INPUTS> jsInputs;
      for(int i = 0; i < ZETH_NUM_JS_INPUTS; i++) {
        proverpkg::JSInput receivedInput = proofInputs->jsinputs(i);
        libzeth::JSInput parsedInput = ParseJSInput(receivedInput);
        jsInputs[i] = parsedInput;
      }

      std::cout << "[DEBUG] Process every outputs of the JoinSplit" << std::endl;
      std::array<libzeth::ZethNote, ZETH_NUM_JS_OUTPUTS> jsOutputs;
      for(int i = 0; i < ZETH_NUM_JS_OUTPUTS; i++) {
        proverpkg::ZethNote receivedOutput = proofInputs->jsoutputs(i);
        libzeth::ZethNote parsedOutput = ParseZethNote(receivedOutput);
        jsOutputs[i] = parsedOutput;
      }
      typedef libsnark::r1cs_ppzksnark_proof<ppT> proofT;
      std::cout << "[DEBUG] Data parsed successfully" << std::endl;
      std::cout << "[DEBUG] Generating the proof..." << std::endl;
      extended_proof<ppT> ext_proof = this->prover.prove(
        root_bits,
        jsInputs,
        jsOutputs,
        vpub_in,
        vpub_out,
        this->keypair.pk
      );

      std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
      dump_proof<ppT>(ext_proof.get_proof());
      display_primary_input<ppT>(ext_proof.get_primary_input());

      std::cout << "[DEBUG] Preparing response..." << std::endl;
      PrepareProofResponse(ext_proof, proof);

    } catch (const std::exception& e) {
      std::cout << "[ERROR] " << e.what() << std::endl;
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, grpc::string(e.what()));
    } catch (...) {
      std::cout << "[ERROR] In catch all" << std::endl;
      return ::grpc::Status(::grpc::StatusCode::UNKNOWN, "");
    }

    return Status::OK;
  }
};

std::string Version() {
  char buffer[100];
  int n;
  n = snprintf(buffer, 100, "Version %d.%d", ZETH_VERSION_MAJOR, ZETH_VERSION_MINOR); // Defined in the zethConfig file
  if (n < 0) {
      return "Version <Not specified>";
  }
  std::string version(buffer);
  return version;
}

void ServerStartMessage() {
  std::string copyright = "Copyright (c) 2015-2019 Clearmatics Technologies Ltd";
  std::string license = "SPDX-License-Identifier: LGPL-3.0+";
  std::string project = "R&D Department: PoC for Zerocash on Ethereum/Autonity";
  std::string version = Version();
  std::string warning = "**WARNING:** This code is a research-quality proof of concept, DO NOT use in production!";

  std::cout << "\n=====================================================" << std::endl;
  std::cout << copyright << std::endl;
  std::cout << license << std::endl;
  std::cout << project << std::endl;
  std::cout << version << std::endl;
  std::cout << warning << std::endl;
  std::cout << "=====================================================\n" << std::endl;
}

void RunServer(
  libzeth::CircuitWrapper<ZETH_NUM_JS_INPUTS, ZETH_NUM_JS_OUTPUTS>& prover,
  keyPairT<ppT>& keypair
) {
  // Listen for incoming connections on 0.0.0.0:50051
  std::string server_address("0.0.0.0:50051");

  ProverImpl service(prover, keypair);

  ServerBuilder builder;

  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);

  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "[DEBUG] Server listening on " << server_address << std::endl;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  ServerStartMessage();
  server->Wait();
}

int main(int argc, char** argv) {
  // We inititalize the curve parameters here
  std::cout << "[DEBUG] Init params" << std::endl;
  ppT::init_public_params();

  std::cout << "[DEBUG] Run setup" << std::endl;
  libzeth::CircuitWrapper<ZETH_NUM_JS_INPUTS, ZETH_NUM_JS_OUTPUTS> prover;
  keyPairT<ppT> keypair = prover.generate_trusted_setup();

  std::cout << "[DEBUG] Setup successful, starting the server..." << std::endl;
  RunServer(prover, keypair);
  return 0;
}
