/* AESmath.hpp
Prototypes common to encryption and decryption */
#ifndef AES_MATH_HPP  
#define AES_MATH_HPP  

#include <array>
#include <vector>

// State size
#define NUM_BYTES 16

unsigned char galoisFieldMult(unsigned char a, unsigned char b);
unsigned char galoisFieldInv(unsigned char a);
unsigned char getSboxValue(unsigned char index);
unsigned char invGetSboxValue(unsigned char index);
void keyExpansion(const std::vector<unsigned char>& key, std::vector<unsigned char>&  expansion, unsigned char keysize);
void addRoundKey(std::array<unsigned char, 16>& state, unsigned char* key);

#endif