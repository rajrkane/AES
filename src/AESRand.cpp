//
// Created by eric on 4/7/21.
//

#include <random>
#include <ios>
#include <iostream>
#include "AESRand.hpp"
#include "encrypt.hpp"

//This uses AES in ctr mode to act as a PRF
//The rng seed is the key that is used for AES

AESRand::AESRand() {
    this->state = std::array<unsigned char, NUM_BYTES>();
    this->key = std::array<unsigned char, RAND_KEY_SIZE>();

    this->seed();
    //Start the counter at zero
    this->state.fill(0);
}

AESRand::~AESRand() {
    //Zero out the arrays to avoid possible information leaking
    this->state.fill(0);
    this->key.fill(0);
}

//Request a vector will numBytes of random data
std::vector<unsigned char> AESRand::generateBytes(unsigned int numBytes) {
    //Prepare the return vector
    std::vector<unsigned char> ret;
    ret.reserve(numBytes);

    unsigned int bytesGenerated = 0;
    unsigned char *data = new unsigned char[NUM_BYTES];

    while (bytesGenerated < numBytes) {
        //Change to use modified encrypt
        //Also using the 256 bit key mode because why not
        encrypt(this->state.data(), data, this->key.data(), this->key.size());

        for (int i = 0; i < NUM_BYTES; i++) {
            //If we have generated the requested number of bytes then stop
            if (bytesGenerated >= numBytes)
                break;
            //Add one byte from the returned data
            //Probably could use array slicing and adding
            ret.push_back(data[i]);
            bytesGenerated++;
        }

        //Increment the state
        for (int i = NUM_BYTES - 1; i >= 0; i--) {
            //Increment the current byte
            this->state[i] = this->state[i] + 1;
            //If the byte did not overflow to zero, then stop
            //Otherwise continue until an overflow does not happen
            if (this->state[i] != 0)
                break;
        }

    }

    delete[] data;

    return ret;
}

//This generates new random numbers for the key
void AESRand::seed() {
    //This is the best source of randomness in the standard library
    //Note: this is highly implementation dependent. This could provide actual hardware entropy or just numbers from a PRG
    //On most linux and windows builds, this should come from cpu random instructions, high precision event counters,
    //user mouse movement and others. But this is not required from the specification.
    std::random_device rd;
    //Fill the key, which acts as the seed with what should be high quality randomness
    for (int i = 0; i < RAND_KEY_SIZE; i += 4) {
        //rd returns 32 or 64 bit numbers, we will take just the first 32 bits
        unsigned int rand = rd();
        this->key[i] = (unsigned char) (rand & 0xFF);
        this->key[i + 1] = (unsigned char) ((rand >> 8) & 0xFF);
        this->key[i + 2] = (unsigned char) ((rand >> 16) & 0xFF);
        this->key[i + 3] = (unsigned char) ((rand >> 24) & 0xFF);
    }
}
