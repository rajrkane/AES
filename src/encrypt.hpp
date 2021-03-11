// encrypt.hpp
#ifndef ENCRYPT_HPP
#define ENCRYPT_HPP 

void keyExpansion(unsigned char* key);
void subBytes(unsigned char* state);
void shiftRows(unsigned char* state);
void mixColumns(unsigned char* state);
void addRoundKey(unsigned char* state);



void encrypt(unsigned char* input, unsigned char* output);


#endif