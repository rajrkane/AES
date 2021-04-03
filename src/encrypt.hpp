// encrypt.hpp
#ifndef ENCRYPT_HPP
#define ENCRYPT_HPP 

#include "AESmath.hpp"

void encrypt(unsigned char* plainInput, unsigned char* encryptedOutput, unsigned char* key, unsigned int keysize);
void subBytes(unsigned char* state);
void shiftRows(unsigned char* state);
void mixColumns(unsigned char* state);

#endif