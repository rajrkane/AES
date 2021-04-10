/**
  @file AESecb.cpp
  Implementation of ECB mode of operation for AES-128 algorithm
*/
#include "AESecb.hpp"
#include <iostream>


void printEncryptOutput(std::vector<unsigned char>& output) {
  std::cout << std::endl;
  std::cout << "Encrypt result";
  for (int i = 0; i < output.size() / 16; i++){
    std::cout << std::endl;
    std::cout << "Block " << i << ": ";
    for (int j = 0; j < 16; j++) {
      std::cout << std::hex << (int) output[j+(i*16)];
      std::cout << " ";
    }
  }
  std::cout << std::endl;
}


/**
  Implements cipher with ECB mode of operation
  @param input: vector of hex values representing plaintext
  @param output: vector of hex values representing (padded) ciphertext
  @param key: vector of hex values representing key to use
  @return none
*/
void encrypt_ecb(const std::vector<unsigned char>& input, std::vector<unsigned char>& output, const std::vector<unsigned char>& key) {  
  // Calculate padding length, then copy input array and padding into plaintext
  const std::size_t inputSize = input.size();
  const std::size_t padLength = 16 - (inputSize % 16);
  const std::size_t plaintextLength = inputSize + padLength;

  // Plaintext accomodates both the input and the necessary padding
  std::vector<unsigned char> plaintext;
  plaintext.reserve(plaintextLength);
  plaintext = input;

  for (int i = 0; i < padLength; i++) {
    // PKCS#7 padding (source: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
    plaintext[inputSize+i] = padLength;
  }

  // Loop over number of blocks
  for (int i = 0; i < plaintextLength / 16; i++) {

    // Loop over block size and fill each block
    std::array<unsigned char, 16> block;
    for (int j = 0; j < 16; j++) {
      block[j] = plaintext[j+(i*16)]; 
    }

    // Encrypt each block
    std::array<unsigned char, 16> outputBlock;
    encrypt(block, outputBlock, key); // TODO: this is sequential, and could be parallelized

    // Copy encrypted block to the output
    for (int j = 0; j < 16; j++) {
      output.push_back(outputBlock[j]);
    }
  }

  printEncryptOutput(output);
}


void printDecryptOutput(std::vector<unsigned char>& output) {
  std::cout << std::endl;
  std::cout << "Decrypt result";
  std::cout << std::endl;
  for (int i = 0; i < output.size(); i++) {
    std::cout << std::hex << (int) output[i];
    std::cout << " ";
  }
  std::cout << std::endl;
}


/**
  Implements inverse cipher with ECB mode of operation
  @param input: vector of hex values representing (padded) ciphertext
  @param output: vector of hex values representing plaintext (without padding)
  @param key: vector of hex values representing key to use
  @return none
*/
void decrypt_ecb(std::vector<unsigned char>& input, std::vector<unsigned char>& output, const std::vector<unsigned char>& key) {
  const std::size_t inputSize = input.size(); 

  // Loop over number of blocks
  for (std::size_t i = 0; i < inputSize / 16; i++) {

    // Loop over block size and fill each block
    std::array<unsigned char, 16> block;
    for (std::size_t j = 0; j < 16; j++) {
      block[j] = input[j+(i*16)];
    }

    // Decrypt each block
    std::array<unsigned char, 16> outputPadded;
    decrypt(block, outputPadded, key);

    // Copy decrypted block to the output
    for (std::size_t j = 0; j < 16; j++) {
      output.push_back(outputPadded[j]);
    }
  }

  const int lastByte = (int) output.back();
  output.erase(output.end() - lastByte, output.end()); // Padding value is also the padding length

  printDecryptOutput(output);
}


// TODO: input, output, key, should be set in main file and passed to each AES___.cpp file
int main() {
  const std::vector<unsigned char> key = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };
  std::vector<unsigned char> output;

  // UNCOMMENT BELOW TO TEST ENCRYPT_ECB
  std::vector<unsigned char> input = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  }; // ENCRYPT TEST INPUT #1
  encrypt_ecb(input, output, key);

  ////////////////////////////////////////

  // UNCOMMENT BELOW TO TEST DECRYPT_ECB
  // std::vector<unsigned char> input = { // vector, not array, because pad leads to variable sizes that are multiples of 16
  //   0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a, 
  //   0x95, 0x4f, 0x64, 0xf2, 0xe4, 0xe8, 0x6e, 0x9e, 0xee, 0x82, 0xd2, 0x02, 0x16, 0x68, 0x48, 0x99 
  // }; // DECRYPT TEST INPUT #1 (note that the decrypt input is padded)
  // decrypt_ecb(input, output, key);
}