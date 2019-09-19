#ifndef __ZETH_MPC_CLI_COMMON_HPP__
#define __ZETH_MPC_CLI_COMMON_HPP__

#include "circuit_types.hpp"

#include <boost/program_options.hpp>
#include <fstream>
#include <map>
#include <string>
#include <vector>

using ProtoboardInitFn = std::function<void(libsnark::protoboard<FieldT> &)>;

class subcommand
{
protected:
    std::string subcommand_name;
    bool verbose;
    ProtoboardInitFn protoboard_init;

private:
    bool help;

public:
    subcommand(const std::string &subcommand_name);
    void set_global_options(bool verbose, ProtoboardInitFn protoboard_init);
    int execute(const std::vector<std::string> &args);

protected:
    void init_protoboard(libsnark::protoboard<FieldT> &pb) const;

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

// interface for ReadableT types:
// {
//     static ReadableT read(std::istream &in);
// }

// Utility function to load data objects from a file, using a static read
// method.  Type must satisfy ReadableT constraints above.
template<typename ReadableT>
inline ReadableT read_from_file(const std::string &file_name)
{
    std::ifstream in(file_name, std::ios_base::binary | std::ios_base::in);
    in.exceptions(
        std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);
    return ReadableT::read(in);
}

// Load data objects from a file, similarly to read_from_file, while computing
// the hash of the serialized structure.  Type must satisfy ReadableT
// constraints above.
template<typename ReadableT>
inline ReadableT read_from_file_and_hash(
    const std::string &file_name, srs_mpc_hash_t out_hash)
{
    std::ifstream inf(file_name, std::ios_base::binary | std::ios_base::in);
    hash_istream_wrapper in(inf);
    in.exceptions(
        std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);
    ReadableT v = ReadableT::read(in);
    in.get_hash(out_hash);
    return v;
}

extern subcommand *mpc_linear_combination_cmd;
extern subcommand *mpc_dummy_phase2_cmd;
extern subcommand *mpc_phase2_begin_cmd;
extern subcommand *mpc_phase2_contribute_cmd;
extern subcommand *mpc_phase2_verify_contribution_cmd;
extern subcommand *mpc_phase2_verify_transcript_cmd;
extern subcommand *mpc_create_keypair_cmd;

/// Main entry point into the mpc command for a given circuit.
int mpc_main(
    int argc,
    char **argv,
    const std::map<std::string, subcommand *> &commands,
    ProtoboardInitFn pb_init);

#endif // __ZETH_MPC_CLI_COMMON_HPP__
