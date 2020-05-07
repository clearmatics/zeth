// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_R1CS_SERIALIZATION_HPP__
#define __ZETH_SERIALIZATION_R1CS_SERIALIZATION_HPP__

#include <ostream>

namespace libzeth
{

template<typename ppT>
std::ostream &r1cs_write_json(
    const libsnark::protoboard<libff::Fr<ppT>> &pb, std::ostream &s);

} // namespace libzeth

#include "libzeth/serialization/r1cs_serialization.tcc"

#endif // __ZETH_SERIALIZATION_R1CS_SERIALIZATION_HPP__
