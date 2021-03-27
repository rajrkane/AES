// decrypt.hpp
#ifndef DECRYPT_HPP
#define DECRYPT_HPP

const int NUM_BYTES;

const unsigned char s_box_inv[256];

void decrypt(unsigned char* input, unsigned char* output, unsigned char* key);

void keyExpansion(unsigned char* key, unsigned char* expansion, unsigned char keysize);

void addRoundKey(unsigned char* state, unsigned char* key);

void subBytesInv(unsigned char* state);

void shiftRowsInv(unsigned char* state);

void mixColumnsInv(unsigned char* state);

#endif