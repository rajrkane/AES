#include <random>
#include <algorithm>
#include "AESRand.hpp"
#include "encrypt.hpp"

/**
  AESRand constructor

  @return none
*/
AESRand::AESRand() {
    //Open /dev/urandom with the input and binary parameter
    this->urandom = std::ifstream("/dev/urandom", std::ios_base::in | std::ios_base::binary);
}

/**
  AESRand deconstructor
  @return none
*/
AESRand::~AESRand() {
    //Close the file
    this->urandom.close();
}

/**
  AESRand::generateBytes
  Generates some number of bytes using Unix/Linux /dev/urandom
  @param numBytes: The number of random bytes needed
  @return A vector with the random bytes
*/
std::vector<unsigned char> AESRand::generateBytes(unsigned int numBytes) {
    std::vector<unsigned char> ret(numBytes, 0);

    //Cast the unsigned char array to a char array since ifstream returns char
    this->urandom.read((char*)ret.data(), numBytes);

    return ret;
}
