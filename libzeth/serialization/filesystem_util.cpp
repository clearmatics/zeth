// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/filesystem_util.hpp"

namespace libzeth
{

boost::filesystem::path get_path_to_setup_directory()
{
    // If the ZETH_SETUP_DIR env var is not set, check HOME, and
    // fallback to current directory.

    const char *path = std::getenv("ZETH_SETUP_DIR");
    if (path != nullptr) {
        return path;
    }

    path = std::getenv("HOME");
    if (path != nullptr) {
        return boost::filesystem::path(path) / "zeth_setup";
    }

    return "";
}

boost::filesystem::path get_path_to_debug_directory()
{
    const char *path = std::getenv("ZETH_DEBUG_DIR");
    if (path != nullptr) {
        return boost::filesystem::path(path);
    }

    // Fallback destination if the ZETH_DEBUG_DIR env var is not set
    // We assume below that `std::getenv("HOME")` does not return `nullptr`
    boost::filesystem::path home_path =
        boost::filesystem::path(std::getenv("HOME"));
    boost::filesystem::path zeth_debug("zeth_debug");
    boost::filesystem::path default_path = home_path / zeth_debug;
    return default_path;
}

} // namespace libzeth
