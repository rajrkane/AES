#ifndef AES_AESRAND_HPP
#define AES_AESRAND_HPP

#include <vector>
#include <array>
#include <random>
#include <iostream>
#include <fstream>
#include "AESmath.hpp"



//AESRand class
class AESRand {
public:
    AESRand();

    ~AESRand();

    std::vector<unsigned char> generateBytes(unsigned int numBytes);

private:
    std::ifstream urandom;
};


#endif //AES_AESRAND_HPP
