#include <iostream>

bool test_dummy()
{
    std::cout << "IN DUMMY TEST" << std::endl;
    return true;
}

int main(void)
{
    std::cout << "IN MAIN() OF TEST" << std::endl;
    bool res = test_dummy();
}
