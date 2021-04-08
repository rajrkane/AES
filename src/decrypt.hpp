// decrypt.hpp
#ifndef DECRYPT_HPP
#define DECRYPT_HPP

#include "AESmath.hpp"
#include <array>

void decrypt(std::array<unsigned char, 16> input, std::array<unsigned char, 16>& output, const std::vector<unsigned char>& key);
void invSubBytes(unsigned char* state);
void invShiftRows(unsigned char* state);
void invMixColumns(unsigned char* state);

#endif