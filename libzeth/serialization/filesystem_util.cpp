// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/filesystem_util.hpp"

namespace libzeth
{

boost::filesystem::path get_path_to_setup_directory()
{
    const char *path = std::getenv("ZETH_TRUSTED_SETUP_DIR");
    if (nullptr == path) {
        // Fallback destination if the ZETH_TRUSTED_SETUP_DIR env var is not set
        // We assume below that `std::getenv("HOME")` does not return `nullptr`
        boost::filesystem::path home_path =
            boost::filesystem::path(std::getenv("HOME"));
        boost::filesystem::path zeth_setup("zeth_setup");
        boost::filesystem::path default_path = home_path / zeth_setup;

        return default_path;
    }

    return boost::filesystem::path(path);
}

boost::filesystem::path get_path_to_debug_directory()
{
    const char *path = std::getenv("ZETH_DEBUG_DIR");
    if (nullptr == path) {
        // Fallback destination if the ZETH_DEBUG_DIR env var is not set
        // We assume below that `std::getenv("HOME")` does not return `nullptr`
        boost::filesystem::path home_path =
            boost::filesystem::path(std::getenv("HOME"));
        boost::filesystem::path zeth_debug("zeth_debug");
        boost::filesystem::path default_path = home_path / zeth_debug;
    }

    return boost::filesystem::path(path);
}

} // namespace libzeth
