#include <boost/program_options.hpp>
#include <fstream>
#include <string>
#include <vector>

class subcommand
{
protected:
    std::string subcommand_name;
    bool verbose;

private:
    bool help;

public:
    subcommand(const std::string &subcommand_name);
    int execute(bool verbose, const std::vector<std::string> &args);

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
