// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libtool/tool_util.hpp"

namespace libtool
{

std::ifstream open_input_binary_file(const std::string &filename)
{
    std::ifstream in_s(
        filename.c_str(), std::ios_base::in | std::ios_base::binary);
    in_s.exceptions(
        std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);
    return in_s;
}

std::ofstream open_output_binary_file(const std::string &filename)
{
    std::ofstream out_s(
        filename.c_str(), std::ios_base::out | std::ios_base::binary);
    return out_s;
}

} // namespace libtool
