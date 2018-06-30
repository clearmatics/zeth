#include "mainCmd.hpp"

void printUsage(std::string program) {
    std::cerr << std::endl;
    std::cerr << "Usage: " << std::endl;
    std::cerr << "\t" << program << " command [arguments]" << std::endl;
    std::cerr << "The commands are:" << std::endl;
    std::cerr << "\t setup \t Run the trusted setup (generate proving and verifying keys)" << std::endl;
    std::cerr << "\t prove \t Generate a proof using the primary input (public), the auxiliary input (private), and the proving key" << std::endl;
}

command_code getCommandCode(std::string command) {
    if (command == "setup") return SETUP;
    if (command == "prove") return PROVE;
    return UNKNOWN;
}
