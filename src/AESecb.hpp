// AESecb.hpp
#ifndef AES_ECB_HPP  
#define AES_ECB_HPP

#include "AESmath.hpp"
#include "encrypt.hpp"
#include "decrypt.hpp"

void encrypt_ecb(std::array<unsigned char, 16>& input, std::array<unsigned char, 16>& output, unsigned char* key, unsigned int keysize);
void decrypt_ecb();

#endif