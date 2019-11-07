#ifndef __ZETH_UTIL_API_HPP__
#define __ZETH_UTIL_API_HPP__

#include "api/util.pb.h"
#include "libsnark_helpers/debug_helpers.hpp"
#include "types/bits.hpp"
#include "types/joinsplit.hpp"
#include "types/note.hpp"
#include "util.hpp"

#include <libff/common/default_types/ec_pp.hpp>

typedef libff::default_ec_pp ppT;

namespace libzeth
{

zeth_note parse_zeth_note(const prover_proto::ZethNote &note);

template<typename FieldT> FieldT parse_merkle_node(std::string mk_node);

template<typename FieldT>
joinsplit_input<FieldT> parse_joinsplit_input(
    const prover_proto::JoinsplitInput &input);

prover_proto::HexPointBaseGroup1Affine format_hexPointBaseGroup1Affine(
    libff::alt_bn128_G1 point);
prover_proto::HexPointBaseGroup2Affine format_hexPointBaseGroup2Affine(
    libff::alt_bn128_G2 point);

} // namespace libzeth
#include "util_api.tcc"

#endif // __ZETH_UTIL_API_HPP__
