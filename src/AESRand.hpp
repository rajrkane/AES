#ifndef AES_AESRAND_HPP
#define AES_AESRAND_HPP

#include <vector>
#include <array>
#include <random>
#include "AESmath.hpp"

//AESRand class
class AESRand {
public:
    AESRand();

    ~AESRand();

    void seed();

    std::vector<unsigned char> generateBytes(unsigned int numBytes);

private:
    std::mt19937 mt19937;
};


#endif //AES_AESRAND_HPP
