/**
  @file decrypt.hpp: Prototypes for decryption
*/
#ifndef DECRYPT_HPP
#define DECRYPT_HPP

#include "AESmath.hpp"
#include <array>



void decrypt(std::array<unsigned char, 16> input, std::array<unsigned char, 16>& output, const std::vector<unsigned char>& key); // Secure coding: DCL52-CPP. Never qualify a reference type with const or volatile
void invSubBytes(std::array<unsigned char, NUM_BYTES>& state);
void invShiftRows(std::array<unsigned char, NUM_BYTES>& state);
void invMixColumns(std::array<unsigned char, NUM_BYTES>& state);

#endif
