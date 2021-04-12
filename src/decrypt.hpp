// decrypt.hpp
#ifndef DECRYPT_HPP
#define DECRYPT_HPP

#include "AESmath.hpp"
#include <array>

void decrypt(std::array<unsigned char, 16> input, std::array<unsigned char, 16>& output, const std::vector<unsigned char>& key);
void invSubBytes(std::array<unsigned char, 16>& state);
void invShiftRows(std::array<unsigned char, 16>& state);
void invMixColumns(std::array<unsigned char, 16>& state);

#endif