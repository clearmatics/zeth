#ifndef __ZETH_UTIL_API_HPP__
#define __ZETH_UTIL_API_HPP__

#include <libff/common/default_types/ec_pp.hpp>

#include "util.hpp"
#include "types/bits.hpp"
#include "util.pb.h"
#include "types/note.hpp"
#include "types/joinsplit.hpp"
#include "libsnark_helpers/debug_helpers.hpp"

typedef libff::default_ec_pp ppT;

namespace libzeth {

ZethNote ParseZethNote(const proverpkg::ZethNote& note);

template<typename FieldT>
FieldT ParseMerkleNode(std::string mk_node);

template<typename FieldT>
JSInput<FieldT> ParseJSInput(const proverpkg::JSInput& input);

proverpkg::HexadecimalPointBaseGroup1Affine FormatHexadecimalPointBaseGroup1Affine(libff::alt_bn128_G1 point);
proverpkg::HexadecimalPointBaseGroup2Affine FormatHexadecimalPointBaseGroup2Affine(libff::alt_bn128_G2 point);

} // libzeth

#include "util_api.tcc"

#endif // __ZETH_UTIL_API_HPP__
