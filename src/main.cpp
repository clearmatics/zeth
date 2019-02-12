#include <iostream>

#include "libsnark_helpers/libsnark_helpers.hpp"
#include "circuits/computation.hpp"
#include "circuits/sha256/sha256_ethereum.hpp"

#include "circuit-wrapper.hpp"

// Include the header of the config file
#include "zethConfig.h"

// The curve is set in the CMakeLists.txt, and should be alt_bn128
// as it is the one implemented in the byzantium precompiled on Ethereum
// See: https://github.com/scipr-lab/libff/blob/master/libff/algebra/curves/alt_bn128/alt_bn128_init.cpp
// For more details on the params of alt_bn128
//
// Here we instantiate our templates to use the curve we want (alt_bn128 as this is the one supported by Ethereum)
//
typedef libff::default_ec_pp ppT; // We use the public paramaters (ppT) of the curve used in the CMakeLists.txt
typedef libff::Fr<ppT> FieldT; // We instantiate the field from the ppT of the curve we use
typedef sha256_ethereum<FieldT> HashT; // We instantiate the hash function with our sha256_ethereum based on the FieldT

int main(int argc, char* argv[]) {
    // Display license and version everytime we invoke zeth
    fprintf(
        stdout,
        "Copyright (c) 2015-2018 Clearmatics Technologies Ltd\n \n \
        SPDX-License-Identifier: LGPL-3.0+\n \
        R&D Department: PoC for Zerocash on Autonity\n \
        Version %d.%d\n \n \
        **Warning:** This code is a research-quality proof of concept, DO NOT USE in production!\n",
        ZETH_VERSION_MAJOR,
        ZETH_VERSION_MINOR
    );

    ppT::init_public_params();
    libzeth::CircuitWrapper<1, 1> prover;
    libsnark::r1cs_ppzksnark_keypair<ppT> keypair = prover.generate_trusted_setup();

    return 0;
}
