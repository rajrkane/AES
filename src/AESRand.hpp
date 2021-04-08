//
// Created by eric on 4/7/21.
//

#ifndef AES_AESRAND_HPP
#define AES_AESRAND_HPP

#include <vector>
#include <array>
#include "AESmath.hpp"

#define RAND_KEY_SIZE 32

//AESRand class
//Generates random numbers using AES in counter mode
//AES works as a PRP and we will feed it a random seed for the key
//Then the input to the cipher will be a counter
//This should work better than any of the included generators in the standard library but is sill not ideal
class AESRand {
public:
    AESRand();

    ~AESRand();

    void seed();

    std::vector<unsigned char> generateBytes(unsigned int numBytes);

private:
    std::array<unsigned char, RAND_KEY_SIZE> key;
    std::array<unsigned char, NUM_BYTES> state;
};


#endif //AES_AESRAND_HPP
