// AESecb.cpp
#include "AESecb.hpp"
#include <iostream>

// encrypt_ecb(plaintextPadded) implements encrypt(plaintextPadded[block], output, key, keysize)
// supp. the key is given. Pass in each block of the plaintext after padding to the encrypt function

void encrypt_ecb(unsigned char* input, int inputSize, unsigned char* output, unsigned char* key, unsigned int keysize) {
  
  int padLength = NUM_BYTES - (inputSize % NUM_BYTES);
  if (inputSize < NUM_BYTES) {
    padLength += NUM_BYTES;
  }
  int plaintextLength = inputSize + padLength;

  unsigned char plaintext[plaintextLength];
  for (int i = 0; i < inputSize; i++) {
    plaintext[i] = input[i];
  }
  for (int i = 0; i < padLength; i++) {
    // pkcs#7 padding: pad with x bytes of integer x
    // source: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method
    plaintext[inputSize+i] = padLength;
  }

  // int numRounds = keysize/4 + 6;
  // encrypt(input, output, key, keysize);

}

// void decrypt_ecb() {

// }

int main() {
  // TODO: input, output, key, keysize should really be set in main file and passed to each AES___.cpp file
  unsigned char input[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  }; // For now, keep input size as fixed to 16
  int inputSize = *(&input + 1) - input;
  unsigned char output[16];
  unsigned char key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };
  int keysize = 16;
  encrypt_ecb(input, inputSize, output, key, keysize);
}

// padding = plaintextLength%NUM_BYTES;
// plaintextLength += padding;
// for (i=0;i<plaintextLength;i++){
//   for (j=0;j<numRounds;j++){
//     tmp = encrypt(plaintext[j])
//     ciphertext = ciphertext.append(tmp);
//   }
// }
