// AESecb.cpp
#include "AESecb.hpp"
#include <iostream>
#include <array>
#include <vector>

// encrypt_ecb(plaintextPadded) implements encrypt(plaintextPadded[block], output, key, keysize)
// supp. the key is given. Pass in each block of the plaintext after padding to the encrypt function

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

  // for (int i=0; i< plaintextLength; i++) {
  //   std::cout << std::hex << (int) plaintext[i];
  //   std::cout << " ";
  // }

  

  // Apply encryption directly to each plaintext block
  for (int i = 0; i < plaintextLength / 16; i++) {
    std::array<unsigned char, 16> block;
    std::cout << "encrypting block: ";
    for (int j = 0; j < 16; j++) {
      block[j] = plaintext[j+(i*16)];
      std::cout << std::hex << (int) block[j] << " ";
    }
    std::cout << std::endl;
    encrypt(block, output, key, keysize);
  }
}



// void decrypt_ecb() {

// }

int main() {
  // TODO: input, output, key, keysize should really be set in main file and passed to each AES___.cpp file
  std::array<unsigned char, 16> input = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };
  std::array<unsigned char, 16> output;
  unsigned char key[NUM_BYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  }; 
  // std::array<unsigned char, NUM_BYTES> key = {
  //   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  // };
  int keysize = 16;
  encrypt_ecb(input, output, key, keysize);
}