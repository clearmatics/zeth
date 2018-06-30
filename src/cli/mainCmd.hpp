#ifndef __CMD_MAIN_HPP__
#define __CMD_MAIN_HPP__

#include <iostream>

enum command_code {
    SETUP,
    PROVE,
    UNKNOWN
};

void printUsage(std::string program);
command_code getCommandCode(std::string command);

#endif
