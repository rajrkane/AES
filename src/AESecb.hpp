// AESecb.hpp
#ifndef AES_ECB_HPP  
#define AES_ECB_HPP

#include "AESmath.hpp"
#include "encrypt.hpp"
#include "decrypt.hpp"

void encrypt_ecb(unsigned char* input, unsigned char* output, unsigned char* key, unsigned int keysize);
void decrypt_ecb();

#endif