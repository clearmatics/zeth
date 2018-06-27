/**
 * @file wraplibsnark.hpp
 * @author Jacob Eberhardt <jacob.eberhardt@tu-berlin.de
 * @author Dennis Kuhnert <dennis.kuhnert@campus.tu-berlin.de>
 * @date 2017
 */

//#ifdef __cplusplus
//extern "C" {
//#endif

#ifndef __WRAPLIBSNARK_H_INCLUDED__
#define __WRAPLIBSNARK_H_INCLUDED__

#include <stdbool.h>
#include <stdint.h>
#include <fstream>
#include <iostream>
#include <cassert>
#include <iomanip>

// Contains definition of alt_bn128 ec public parameters
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

// Contains required interfaces and types (keypair, proof, generator, prover, verifier)
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

libff::bigint<libff::alt_bn128_r_limbs> libsnarkBigintFromBytes(const uint8_t* _x);
std::string HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x);
std::string outputPointG1AffineAsHex(libff::alt_bn128_G1 _p);
std::string outputPointG2AffineAsHex(libff::alt_bn128_G2 _p);
r1cs_ppzksnark_keypair<libff::alt_bn128_pp> generateKeypair(const r1cs_ppzksnark_constraint_system<libff::alt_bn128_pp> &cs);

template<typename T> void writeToFile(std::string path, T& obj);
template<typename T> T loadFromFile(std::string path);

void serializeProvingKeyToFile(r1cs_ppzksnark_proving_key<libff::alt_bn128_pp> pk, const char* pk_path);
r1cs_ppzksnark_proving_key<libff::alt_bn128_pp> deserializeProvingKeyFromFile(const char* pk_path);
void serializeVerificationKeyToFile(r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> vk, const char* vk_path);
r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> deserializeVerificationKeyFromFile(const char* vk_path);

void exportVerificationKey(r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair);
void printProof(r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof);

//#ifdef __cplusplus
//} // extern "C"
#endif
