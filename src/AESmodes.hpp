// AESmodes.hpp
#ifndef AES_MODES_HPP  
#define AES_MODES_HPP

#include "AESmath.hpp"
#include "encrypt.hpp"
#include "decrypt.hpp"
#include <vector>

void encrypt_ecb(const std::vector<unsigned char>& input, std::vector<unsigned char>& output, const std::vector<unsigned char>& key);
void decrypt_ecb(std::vector<unsigned char>& input, std::vector<unsigned char>& output, const std::vector<unsigned char>& key);

void encrypt_cbc(const std::vector<unsigned char>& input, std::vector<unsigned char>& output, const std::vector<unsigned char>& key, const std::vector<unsigned char>& IV);
void decrypt_cbc(std::vector<unsigned char>& input, std::vector<unsigned char>& output, const std::vector<unsigned char>& key, const std::vector<unsigned char>& IV);

void printEncryptOutput(std::vector<unsigned char>& output);
void printDecryptOutput(std::vector<unsigned char>& output);

#endif