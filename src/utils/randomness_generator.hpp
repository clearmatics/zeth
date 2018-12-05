#ifndef __RANDOMNESS_HPP__
#define __RANDOMNESS_HPP__

#include <sstream>
#include <iostream>
#include <string.h>

#include <openssl/rand.h>

// generate_random_number() generates a random
// hexadecimal number and returns it
std::string generate_random_number();

#endif
