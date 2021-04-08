// AESecb.hpp
#ifndef AES_ECB_HPP  
#define AES_ECB_HPP

#include "AESmath.hpp"
#include "encrypt.hpp"
#include "decrypt.hpp"
#include <vector>

void encrypt_ecb(const std::vector<unsigned char>& input, std::vector<unsigned char>& output, const std::vector<unsigned char>& key);
void decrypt_ecb(std::vector<unsigned char>& input, std::vector<unsigned char>& output, const std::vector<unsigned char>& key);

#endif