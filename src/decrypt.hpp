// decrypt.hpp
#ifndef DECRYPT_HPP
#define DECRYPT_HPP

#include "AESmath.hpp"

void decrypt(unsigned char* input, unsigned char* output, unsigned char* key, int keysize);
void invSubBytes(unsigned char* state);
void invShiftRows(unsigned char* state);
void invMixColumns(unsigned char* state);

#endif