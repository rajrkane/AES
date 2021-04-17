/**
  @file AESmodes.hpp: prototypes for modes of operation functions
*/
#ifndef AES_MODES_HPP
#define AES_MODES_HPP

#include "AESmath.hpp"
#include "encrypt.hpp"
#include "decrypt.hpp"
#include <vector>

bool remove_padding(std::vector<unsigned char> &input) noexcept(false);

bool encrypt_ecb(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key) noexcept(true);

bool decrypt_ecb(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key) noexcept(true);

bool encrypt_cbc(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) noexcept(true);

bool decrypt_cbc(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) noexcept(true);

bool encrypt_ctr(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key,
                 const std::array<unsigned char, NUM_BYTES / 2> &nonce) noexcept(true);

bool decrypt_ctr(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key,
                 const std::array<unsigned char, NUM_BYTES / 2> &nonce) noexcept(true);

bool encrypt_cfb(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) noexcept(true);

bool decrypt_cfb(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) noexcept(true);

bool encrypt_ofb(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) noexcept(true);

bool decrypt_ofb(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) noexcept(true);

void printEncryptOutput(std::vector<unsigned char> &output);

void printDecryptOutput(std::vector<unsigned char> &output);

#endif
