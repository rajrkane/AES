// AESecb.hpp
#ifndef AES_ECB_HPP  
#define AES_ECB_HPP

#include "AESmath.hpp"
#include "encrypt.hpp"
#include "decrypt.hpp"
#include <array>
#include <vector>

void encrypt_ecb(std::array<unsigned char, 16>& input, std::vector<unsigned char>& output, unsigned char* key, unsigned int keysize);
void decrypt_ecb(std::vector<unsigned char>& input, std::vector<unsigned char>& output, unsigned char* key, unsigned int keysize);

#endif