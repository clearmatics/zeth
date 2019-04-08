// DISCLAIMER:
// Content taken and adapted from:
// wraplibsnark.cpp (originally written by Jacob Eberhardt and Dennis Kuhnert)

#include "libsnark_helpers/debug_helpers.hpp"

namespace libzeth {

// Conversion byte[32] <-> libsnark bigint.
libff::bigint<libff::alt_bn128_r_limbs> libsnarkBigintFromBytes(const uint8_t* _x)
{
    libff::bigint<libff::alt_bn128_r_limbs> x;

    for (unsigned i = 0; i < 4; i++)
    {
        for (unsigned j = 0; j < 8; j++)
        {
            x.data[3 - i] |= uint64_t(_x[i * 8 + j]) << (8 * (7-j));
        }
    }
    return x;
}

std::string HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x)
{
    uint8_t x[32];
    for (unsigned i = 0; i < 4; i++)
    {
        for (unsigned j = 0; j < 8; j++)
        {
            x[i * 8 + j] = uint8_t(uint64_t(_x.data[3 - i]) >> (8 * (7 - j)));
        }
    }
    
    std::stringstream ss;
    ss << std::setfill('0');
    for (unsigned i = 0; i<32; i++)
    {
        ss << std::hex << std::setw(2) << (int)x[i];
    }

    std::string str = ss.str();
    return str.erase(0, std::min(str.find_first_not_of('0'), str.size()-1));
}

std::string outputPointG1AffineAsHex(libff::alt_bn128_G1 _p)
{
    libff::alt_bn128_G1 aff = _p;
    aff.to_affine_coordinates();
    return
        "\"0x" +
        HexStringFromLibsnarkBigint(aff.X.as_bigint()) +
        "\", \"0x" +
        HexStringFromLibsnarkBigint(aff.Y.as_bigint()) +
        "\"";
}

std::string outputPointG2AffineAsHex(libff::alt_bn128_G2 _p)
{
    libff::alt_bn128_G2 aff = _p;
    aff.to_affine_coordinates();
    return
        "[\"0x" +
        HexStringFromLibsnarkBigint(aff.X.c1.as_bigint()) + "\", \"0x" +
        HexStringFromLibsnarkBigint(aff.X.c0.as_bigint()) + "\"],\n [\"0x" +
        HexStringFromLibsnarkBigint(aff.Y.c1.as_bigint()) + "\", \"0x" +
        HexStringFromLibsnarkBigint(aff.Y.c0.as_bigint()) + "\"]";
}

std::string outputPointGTAffineAsHex(libff::alt_bn128_GT _p)
{
    libff::alt_bn128_GT aff = _p;
    aff.to_affine_coordinates();
    return
        "[\"0x" +
        HexStringFromLibsnarkBigint(aff.X.c1.as_bigint()) + "\", \"0x" +
        HexStringFromLibsnarkBigint(aff.X.c0.as_bigint()) + "\"],\n [\"0x" +
        HexStringFromLibsnarkBigint(aff.Y.c1.as_bigint()) + "\", \"0x" +
        HexStringFromLibsnarkBigint(aff.Y.c0.as_bigint()) + "\"]";
}

boost::filesystem::path getPathToSetupDir()
{
    char* pathToSetupFolder;
    pathToSetupFolder = std::getenv("ZETH_TRUSTED_SETUP_DIR");
    if (pathToSetupFolder == NULL)
    {
        // Fallback destination if the ZETH_TRUSTED_SETUP_DIR env var is not set
        pathToSetupFolder = "../trusted_setup";
    }

    boost::filesystem::path setup_dir(pathToSetupFolder);
    return setup_dir;
}

boost::filesystem::path getPathToDebugDir()
{
    char* pathToDebugFolder;
    pathToDebugFolder = std::getenv("ZETH_DEBUG_DIR");
    if (pathToDebugFolder == NULL)
    {
        // Fallback destination if the ZETH_DEBUG_DIR env var is not set
        pathToDebugFolder = "../debug";
    }

    boost::filesystem::path setup_dir(pathToDebugFolder);
    return setup_dir;
}


bool replace(std::string& str, const std::string& from, const std::string& to)
{
    size_t start_pos = str.find(from);
    if(start_pos == std::string::npos)
    {
        return false;
    }

    str.replace(start_pos, from.length(), to);
    return true;
}

} // libzeth