/* AESmath.hpp
Prototypes common to encryption and decryption */
#ifndef AES_MATH_HPP  
#define AES_MATH_HPP  

#define NUM_BYTES 16

unsigned char galoisFieldMult(unsigned char a, unsigned char b);

unsigned char galoisFieldInv(unsigned char a);

unsigned char getSboxValue(unsigned char index);

void keyExpansion(unsigned char* key, unsigned char* expansion, unsigned char keysize);

void addRoundKey(unsigned char* state, unsigned char* key);

#endif