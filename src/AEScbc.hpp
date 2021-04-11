// AESecb.hpp
#ifndef AES_CBC_HPP  
#define AES_CBC_HPP

#include "AESmath.hpp"
#include "encrypt.hpp"
#include "decrypt.hpp"
#include <vector>

// TODO: the functions should take in the IV as a parameter
void encrypt_cbc(const std::vector<unsigned char>& input, std::vector<unsigned char>& output, const std::vector<unsigned char>& key, const std::vector<unsigned char>& IV);
void decrypt_cbc(std::vector<unsigned char>& input, std::vector<unsigned char>& output, const std::vector<unsigned char>& key, const std::vector<unsigned char>& IV);

#endif