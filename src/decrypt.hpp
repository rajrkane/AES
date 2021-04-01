// decrypt.hpp
#ifndef DECRYPT_HPP
#define DECRYPT_HPP

void decrypt(unsigned char* input, unsigned char* output, unsigned char* key, int keysize);

void subBytesInv(unsigned char* state);

void shiftRowsInv(unsigned char* state);

void mixColumnsInv(unsigned char* state);

#endif