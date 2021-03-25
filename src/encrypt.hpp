// encrypt.hpp
#ifndef ENCRYPT_HPP
#define ENCRYPT_HPP 

void encrypt(unsigned char* plainInput, unsigned char* encryptedOutput, unsigned char* key, unsigned int keysize);

void keyExpansion(unsigned char* key, unsigned char* expansion, unsigned char keysize);

void addRoundKey(unsigned char* state, unsigned char* key);

void subBytes(unsigned char* state);

void shiftRows(unsigned char* state);

void mixColumns(unsigned char* state);

unsigned char galoisFieldMult(unsigned char a, unsigned char b);
unsigned char galoisFieldInv(unsigned char a);
unsigned char getSboxValue(unsigned char index);

#endif