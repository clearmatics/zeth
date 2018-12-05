#include "randomness_generator.hpp"

// generate_random_number() generates a random
// hexadecimal number and returns it
std::string generate_random_number() {
    // Get the randomnes (PRNG)
	unsigned char rnd[256];
    RAND_pseudo_bytes(rnd, sizeof(rnd));

    // Store the PRN in an hexadecimal st
    std::stringstream ss;
    for(int i=0; i < strlen((char*)rnd); ++i)
            ss << std::hex << (int)rnd[i];

    return ss.str();

}
