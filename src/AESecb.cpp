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
}


/**
  Implements cipher with ECB mode of operation
  @param input: array of hex values representing plaintext
  @param output: array of hex values representing (padded) ciphertext
  @param key: key to use
  @param keysize: size of the key
  @return array of decrypted values
*/
void encrypt_ecb(std::array<unsigned char, 16>& input, std::vector<unsigned char>& output, unsigned char* key, unsigned int keysize) {

  // Calculate padding length, then copy input array and padding into plaintext
  const int inputSize = input.size();
  const int padLength = 16 - (inputSize % 16);
  const int plaintextLength = inputSize + padLength;

  std::vector<unsigned char> plaintext;
  plaintext.reserve(plaintextLength);

  for (int i = 0; i < inputSize; i++) {
    plaintext[i] = input[i];
  }

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
    encrypt(block, outputBlock, key, keysize); // TODO: this is sequential, and could be parallelized

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
}


/**
  Implements inverse cipher with ECB mode of operation
  @param input: vector of hex values representing (padded) ciphertext
  @param output: vector of hex values representing plaintext (without padding)
  @param key: key to use
  @param keysize: size of the key
  @return none
*/
void decrypt_ecb(std::vector<unsigned char>& input, std::vector<unsigned char>& output, unsigned char* key, unsigned int keysize) {

  const int inputSize = input.size(); 

  // Loop over number of blocks
  for (int i = 0; i < inputSize / 16; i++) {

    // Loop over block size and fill each block
    std::array<unsigned char, 16> block;
    for (int j = 0; j < 16; j++) {
      block[j] = input[j+(i*16)];
    }

    // Decrypt each block
    std::array<unsigned char, 16> outputPadded;
    decrypt(block, outputPadded, key, keysize);

    // Copy decrypted block to the output
    for (int j = 0; j < 16; j++) {
      output.push_back(outputPadded[j]);
    }
  }

  const int lastByte = (int) output.back();
  output.erase(output.end() - lastByte, output.end()); // Padding value is also the padding length

  printDecryptOutput(output);
}


// TODO: input, output, key, keysize should be set in main file and passed to each AES___.cpp file
int main() {

  unsigned char key[NUM_BYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };
  int keysize = 16;
  std::vector<unsigned char> output;

  // UNCOMMENT BELOW TO TEST ENCRYPT_ECB
  std::array<unsigned char, 16> input = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  }; // ENCRYPT TEST INPUT #1
  encrypt_ecb(input, output, key, keysize);

  ////////////////////////////////////////

  // UNCOMMENT BELOW TO TEST DECRYPT_ECB
  // std::vector<unsigned char> input = { // vector, not array, because pad leads to variable sizes that are multiples of 16
  //   0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a, 
  //   0x95, 0x4f, 0x64, 0xf2, 0xe4, 0xe8, 0x6e, 0x9e, 0xee, 0x82, 0xd2, 0x02, 0x16, 0x68, 0x48, 0x99 
  // }; // DECRYPT TEST INPUT #1 (note that the decrypt input is padded)
  // decrypt_ecb(input, output, key, keysize);
}