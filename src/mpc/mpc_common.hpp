#ifndef __ZETH_MPC_MPC_COMMON_HPP__
#define __ZETH_MPC_MPC_COMMON_HPP__

#include "include_libsnark.hpp"

#include <boost/program_options.hpp>
#include <fstream>
#include <string>
#include <vector>

using ppT = libff::default_ec_pp;
using FieldT = libff::Fr<ppT>;

class subcommand
{
protected:
    std::string subcommand_name;
    bool verbose;
    bool simple_circuit;

private:
    bool help;

public:
    subcommand(const std::string &subcommand_name);
    void set_global_options(bool verbose, bool simple_circuit);
    int execute(const std::vector<std::string> &args);

private:
    void usage(const boost::program_options::options_description &all_options);

    virtual void initialize_suboptions(
        boost::program_options::options_description &options,
        boost::program_options::options_description &all_options,
        boost::program_options::positional_options_description &pos) = 0;
    virtual void parse_suboptions(
        const boost::program_options::variables_map &vm) = 0;
    virtual void subcommand_usage() = 0;
    virtual int execute_subcommand() = 0;
};

// Utility function to load data objects from a file, using a static read
// method.
template<typename T> inline T read_from_file(const std::string &file_name)
{
    std::ifstream in(file_name, std::ios_base::binary | std::ios_base::in);
    in.exceptions(
        std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);
    return T::read(in);
}

void populate_protoboard(
    libsnark::protoboard<libff::Fr<ppT>> &pb, bool simple_circuit);

#endif // __ZETH_MPC_MPC_COMMON_HPP__
