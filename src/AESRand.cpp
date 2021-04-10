#include <random>
#include <algorithm>
#include "AESRand.hpp"
#include "encrypt.hpp"

/**
  AESRand constructor

  @return none
*/
AESRand::AESRand() {
    //Some compilers will complain that a default seed is being used
    //The method seed will seed this
    this->mt19937 = std::mt19937();
    this->seed();
}

/**
  AESRand deconstructor
  @return none
*/
AESRand::~AESRand() {
    //Reset the state of the PRG
    //Probably does not need to happen but I'm paranoid
    this->mt19937.seed(0);
}

/**
  AESRand::seed
  This seeds the state of the Mersenne Twister engine used as a PRG
  As shown in class, seeding a prg with random numbers will produce indistinguishably random output
  Also see MSC51-CPP
  @return none
*/
void AESRand::seed() {
    //Completely seed the entire state of the mt19937 engine
    //The standard way of seeding the engine is by passing in a unsigned int as a parameter in the constructor
    //This is only 32 bits of entropy for a huge (19937 bits) internal state
    //We seed the entire state this way with the entropy from std::random_device
    //This is the best source of randomness in the standard library
    //Note: this is highly implementation dependent. This could provide actual hardware entropy or just numbers from a PRG
    //On most linux and windows builds, this should come from cpu random instructions, high precision event counters,
    //user mouse movement and others. But this is not required from the specification.
    std::array<unsigned int, std::mt19937::state_size> rand_data{};
    std::random_device rd;
    for (unsigned int& i : rand_data)
    {
        i = rd();
    }

    std::seed_seq seeds(rand_data.begin(), rand_data.end());
    this->mt19937.seed(seeds);
}

/**
  AESRand::generateBytes
  Generates some number of bytes using the MT19937 engine
  @param numBytes: The number of random bytes needed
  @return A vector with the random bytes
*/
std::vector<unsigned char> AESRand::generateBytes(unsigned int numBytes) {
    std::vector<unsigned char> ret(numBytes, 0);

    std::size_t bytesGenerated = 0;

    //Uniformly distribute the output from the twister to be in the range of a byte
    std::uniform_int_distribution<> distrib(0, 255);

    while (bytesGenerated < numBytes)
    {
        ret[bytesGenerated] = (unsigned char) distrib(this->mt19937);
        bytesGenerated++;
    }
    return ret;
}
