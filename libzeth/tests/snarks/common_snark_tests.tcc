// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_TESTS_SNARKS_COMMON_SNARK_TESTS_TCC__
#define __ZETH_TESTS_SNARKS_COMMON_SNARK_TESTS_TCC__

#include "libzeth/tests/circuits/simple_test.hpp"

#include <iostream>
#include <sstream>

namespace libzeth
{

namespace tests
{

static const size_t DUMMY_NUM_PRIMARY_INPUTS = 37;

template<typename ppT, typename snarkT>
typename snarkT::proving_key dummy_proving_key()
{
    using Field = libff::Fr<ppT>;
    libsnark::protoboard<Field> pb;
    libzeth::tests::simple_circuit(pb);
    libzeth::tests::simple_circuit(pb);
    libzeth::tests::simple_circuit(pb);
    libzeth::tests::simple_circuit(pb);

    typename snarkT::keypair keypair = snarkT::generate_setup(pb);
    return keypair.pk;
}

template<typename ppT, typename snarkT>
bool verification_key_read_write_bytes_test()
{
    const typename snarkT::verification_key vk =
        snarkT::verification_key::dummy_verification_key(
            DUMMY_NUM_PRIMARY_INPUTS);

    std::string buffer = ([&vk]() {
        std::stringstream ss;
        snarkT::verification_key_write_bytes(vk, ss);
        return ss.str();
    })();

    typename snarkT::verification_key vk2;
    {
        std::stringstream ss(buffer);
        snarkT::verification_key_read_bytes(vk2, ss);
    }

    return vk == vk2;
}

template<typename ppT, typename snarkT> bool proving_key_read_write_bytes_test()
{
    const typename snarkT::proving_key pk = dummy_proving_key<ppT, snarkT>();

    std::string buffer = ([&pk]() {
        std::stringstream ss;
        snarkT::proving_key_write_bytes(pk, ss);
        return ss.str();
    })();

    typename snarkT::proving_key pk2;
    {
        std::stringstream ss(buffer);
        snarkT::proving_key_read_bytes(pk2, ss);
    }

    return pk == pk2;
}

} // namespace tests

} // namespace libzeth

#endif // __ZETH_TESTS_SNARKS_COMMON_SNARK_TESTS_TCC__
