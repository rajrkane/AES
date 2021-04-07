// encrypt.hpp
#ifndef ENCRYPT_HPP
#define ENCRYPT_HPP 

#include "AESmath.hpp"
#include <array>

void encrypt(std::array<unsigned char, 16>& input, std::array<unsigned char, 16>& output, unsigned char* key, unsigned int keysize);
void subBytes(unsigned char* state);
void shiftRows(unsigned char* state);
void mixColumns(unsigned char* state);

#endif