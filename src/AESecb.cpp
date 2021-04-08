// AESecb.cpp
#include "AESecb.hpp"
#include <iostream>


void encrypt_ecb(std::array<unsigned char, 16>& input, std::array<unsigned char, 16>& output, unsigned char* key, unsigned int keysize) {

  // Calculate padding length, then copy input array and padding into plaintext
  const int inputSize = input.size();
  const int padLength = 16 - (inputSize % 16);
  const int plaintextLength = inputSize + padLength;

  std::array<unsigned char, plaintextLength> plaintext;

  for (int i = 0; i < inputSize; i++) {
    plaintext[i] = input[i];
  }

  for (int i = 0; i < padLength; i++) {
    // PKCS#7 padding (source: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
    plaintext[inputSize+i] = padLength;
  }

  // Apply encryption directly to each plaintext block
  for (int i = 0; i < plaintextLength / 16; i++) {
    std::array<unsigned char, 16> block;
    for (int j = 0; j < 16; j++) {
      block[j] = plaintext[j+(i*16)]; 
    }
    encrypt(block, output, key, keysize); // TODO: this is sequential, and could be parallelized
  }
}


void decrypt_ecb(std::vector<unsigned char>& input, std::vector<unsigned char>& output, unsigned char* key, unsigned int keysize) {

  const int inputSize = input.size(); 
  std::vector<unsigned char> plaintext;

  // Loop over number of blocks
  for (int i = 0; i < inputSize / 16; i++) {

    // Loop over block size and generate each block from input
    std::array<unsigned char, 16> block;
    for (int j = 0; j < 16; j++) {
      block[j] = input[j+(i*16)];
    }

    // Decrypt each block
    // std::array<unsigned char, 16> decryptedBlock = decrypt(block, output, key, keysize);
    std::array<unsigned char, 16> outputPadded;
    decrypt(block, outputPadded, key, keysize);
    for (int j = 0; j < 16; j++) {
      output.push_back(outputPadded[j]);
      
    }
    
  }
  for (int j = 0; j < output.size(); j++) {
      std::cout << std::hex << (int) output[j] << " ";
  }

  // Calculate the padding
  // const int lastByte = (int) plaintext.back();
  // std::vector<unsigned char> padding = std::vector<unsigned char>(plaintext.end() - lastByte, plaintext.end());
  // for (int i = 0; i < plaintext.size() - padding.size(); i++) {
  //   output[i] = plaintext[i];
  //   std::cout << output[i] << " ";
  // }


  // for (int i = inputSize-1; i > inputSize-1 - lastByte; i--){
  //   // padding[i] = input[i];
  //   std::cout << i << " ";// padding[i] << " ";
  // }
}


// TODO: input, output, key, keysize should really be set in main file and passed to each AES___.cpp file
int main() {
  // TEST INPUT FOR ENCRYPT_ECB
  // std::array<unsigned char, 16> input = {
  //   0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  // };
  // std::array<unsigned char, 16> output;
  // TEST INPUT (PADDED) FOR DECRYPT_ECB
  std::vector<unsigned char> input = { // vector, not array, because pad leads to variable sizes that are multiples of 16
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a, 
    0x95, 0x4f, 0x64, 0xf2, 0xe4, 0xe8, 0x6e, 0x9e, 0xee, 0x82, 0xd2, 0x02, 0x16, 0x68, 0x48, 0x99 
  };
  std::vector<unsigned char> output;
  unsigned char key[NUM_BYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  }; 
  // std::array<unsigned char, NUM_BYTES> key = {
  //   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  // };
  int keysize = 16;
  decrypt_ecb(input, output, key, keysize);
}