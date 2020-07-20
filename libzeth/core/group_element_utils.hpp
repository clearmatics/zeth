// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_GROUP_ELEMENT_UTILS_HPP__
#define __ZETH_CORE_GROUP_ELEMENT_UTILS_HPP__

#include "include_libff.hpp"

namespace libzeth
{

/// Convert a group element of G1 to a json string (array of hexadecimal
/// strings). This function assumes that the group element is in affine form,
/// and that both coordinates (X, Y) are elements of a prime field.
template<typename ppT>
std::string point_g1_affine_to_json(const libff::G1<ppT> &point);

/// Convert a JSON string into a group element
template<typename ppT>
libff::G1<ppT> point_g1_affine_from_json(const std::string &grp_str);

/// Convert a group element of G2 to a json string (list of hexadecimal
/// strings). This function assumes that the group element is in affine form,
/// and that both coordinates (X, Y) are elements of an extension field which
/// is not built as a tower. Both X and Y are written in "human readable"
/// order, i.e. the coefficients of the polynomial are written from higher
/// degree to smaller (e.g. E = [c2, c1, c0], where E = c2 * x^2 + c1 * x + c0)
template<typename ppT>
std::string point_g2_affine_to_json(const libff::G2<ppT> &point);

} // namespace libzeth

#include "libzeth/core/group_element_utils.tcc"

#endif // __ZETH_CORE_GROUP_ELEMENT_UTILS_HPP__
