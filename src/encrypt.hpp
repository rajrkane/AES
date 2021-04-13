// encrypt.hpp
#ifndef ENCRYPT_HPP
#define ENCRYPT_HPP 

#include "AESmath.hpp"
#include <array>

void encrypt(std::array<unsigned char, 16>& input, std::array<unsigned char, 16>& output, const std::vector<unsigned char>& key);
void subBytes(std::array<unsigned char, NUM_BYTES>& state);
void shiftRows(std::array<unsigned char, NUM_BYTES>& state);
void mixColumns(std::array<unsigned char, NUM_BYTES>& state);

#endif