#include <iostream>
#include "randomness_generator.hpp"

int main() {
    std::string rnd_str = generate_random_number();
    std::cout << "Random string: " << rnd_str << std::endl;

    return 0;
}
