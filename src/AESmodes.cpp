/**
  @file AESmodes.cpp
  Implementation of ECB and CBC modes of operation for AES-128
*/
#include "AESmodes.hpp"
#include <iostream>


void printEncryptOutput(std::vector<unsigned char> &output) {
    std::cout << std::endl;
    std::cout << "Encrypt result";
    for (int i = 0; i < output.size() / 16; i++) {
        std::cout << std::endl;
        std::cout << "Block " << i << ": ";
        for (int j = 0; j < 16; j++) {
            std::cout << std::hex << (int) output[j + (i * 16)];
            std::cout << " ";
        }
    }
    std::cout << std::endl;
}


void printDecryptOutput(std::vector<unsigned char> &output) {
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
  Cipher with ECB mode
  @param input: vector of hex values representing plaintext
  @param output: vector of hex values representing (padded) ciphertext
  @param key: vector of hex values representing key to use
  @return none
*/
void encrypt_ecb(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key) {
    // Calculate padding length, then copy input array and padding into plaintext
    const std::size_t inputSize = input.size();
    const std::size_t padLength = 16 - (inputSize % 16);
    const std::size_t plaintextLength = inputSize + padLength;

    // Plaintext accomodates both the input and the necessary padding
    std::vector<unsigned char> plaintext;
    plaintext.reserve(plaintextLength);
    plaintext = input;

    // TODO: ECB and CBC both repeat this code for padding. Cleaner for padding to have its own function
    for (std::size_t i = 0; i < padLength; i++) {
        // PKCS#7 padding (source: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
        plaintext[inputSize + i] = padLength;
    }

    // Loop over number of blocks
    for (std::size_t i = 0; i < plaintextLength / 16; i++) {

        // Loop over block size and fill each block
        std::array<unsigned char, 16> block;
        for (std::size_t j = 0; j < 16; j++) {
            block[j] = plaintext[j + (i * 16)];
        }

        // Encrypt each block
        std::array<unsigned char, 16> outputBlock;
        encrypt(block, outputBlock, key); // TODO: this is sequential, and could be parallelized

        // Copy encrypted block to the output
        for (std::size_t j = 0; j < 16; j++) {
            output.push_back(outputBlock[j]);
        }
    }

    printEncryptOutput(output);
}


/**
  Inverse cipher with ECB mode
  @param input: vector of hex values representing (padded) ciphertext
  @param output: vector of hex values representing plaintext (without padding)
  @param key: vector of hex values representing key to use
  @return none
*/
void decrypt_ecb(std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key) {
    const std::size_t inputSize = input.size();

    // Loop over number of blocks
    for (std::size_t i = 0; i < inputSize / 16; i++) {

        // Loop over block size and fill each block
        std::array<unsigned char, 16> block;
        for (std::size_t j = 0; j < 16; j++) {
            block[j] = input[j + (i * 16)];
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


/**
  Cipher with CBC mode
  @param input: vector of hex values representing plaintext
  @param output: vector of hex values representing (padded) ciphertext
  @param key: vector of hex values representing key to use
  @param IV: initialization vector to use
  @return none
*/
void encrypt_cbc(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) {
    // Calculate padding length, then copy input array and padding into plaintext
    const std::size_t inputSize = input.size();
    const std::size_t padLength = 16 - (inputSize % 16);
    const std::size_t plaintextLength = inputSize + padLength;

    // Plaintext accomodates both the input and the necessary padding
    std::vector<unsigned char> plaintext;
    plaintext.reserve(plaintextLength);
    plaintext = input;

    // TODO: investigate whether PKCS#7 is the best choice for padding (padding oracle attack)
    for (std::size_t i = 0; i < padLength; i++) {
        // PKCS#7 padding (source: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
        plaintext[inputSize + i] = padLength;
    }

    // Encrypt the first block
    std::array<unsigned char, 16> block;
    for (std::size_t j = 0; j < 16; j++) {
        block[j] = plaintext[j] ^ IV[j];
    }

    std::array<unsigned char, 16> outputBlock;
    encrypt(block, outputBlock, key);

    for (std::size_t j = 0; j < 16; j++) {
        output.push_back(outputBlock[j]);
    }

    // Loop over the number of subsequent blocks
    for (std::size_t i = 1; i < plaintextLength / 16; i++) {
        // Loop over block size and fill each block
        //std::array<unsigned char, 16> block;
        for (std::size_t j = 0; j < 16; j++) {
            block[j] = plaintext[j + (i * 16)] ^ output[j + ((i - 1) * 16)];
        }

        // Encrypt each block
        //std::array<unsigned char, 16> outputBlock;
        encrypt(block, outputBlock, key);

        // Copy encrypted block to the output
        for (std::size_t j = 0; j < 16; j++) {
            output.push_back(outputBlock[j]);
        }
    }

    printEncryptOutput(output);
}


/**
  Inverse cipher with CBC mode
  @param input: vector of hex values representing (padded) ciphertext
  @param output: vector of hex values representing plaintext (without padding)
  @param key: vector of hex values representing key to use
  @param IV: initialization vector to use
  @return none
*/
void decrypt_cbc(std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) {
    const std::size_t inputSize = input.size();

    // Decrypt the first block
    std::array<unsigned char, 16> block;
    for (std::size_t i = 0; i < 16; i++) {
        block[i] = input[i];
    }

    std::array<unsigned char, 16> outputPadded;
    decrypt(block, outputPadded, key);

    for (std::size_t i = 0; i < 16; i++) {
        outputPadded[i] ^= IV[i];
        output.push_back(outputPadded[i]);
    }

    // Loop over the number of subsequent blocks
    for (std::size_t i = 1; i < inputSize / 16; i++) {

        // Loop over block size and fill each block
        //std::array<unsigned char, 16> block;
        for (std::size_t j = 0; j < 16; j++) {
            block[j] = input[j + (i * 16)];
        }

        // Decrypt each block
        //std::array<unsigned char, 16> outputPadded;
        decrypt(block, outputPadded, key);

        // Copy decrypted block to the output
        for (std::size_t j = 0; j < 16; j++) {
            outputPadded[j] ^= input[j + ((i - 1) * 16)];
            output.push_back(outputPadded[j]);
        }
    }


    // Remove padding
    const int lastByte = (int) output.back();
    output.erase(output.end() - lastByte, output.end());

    printDecryptOutput(output);
}

/**
  increments the counter block by one
  @param counter: array of values containing a nonce and a counter section
  @param numCounterBytes: the number of bytes in the counter array that are actually part of the counter
  @return none
*/
void incrementCounter(std::array<unsigned char, NUM_BYTES> &counter, int numCounterBytes) {
    for (int i = NUM_BYTES - 1; i >= numCounterBytes; i--) {
        //Increment the current byte
        counter[i] = counter[i] + 1;
        //If the byte did not overflow to zero, then stop
        //Otherwise continue until an overflow does not happen
        if (counter[i] != 0)
            break;
    }
}

/**
  cipher with CTR mode
  @param input: vector of hex values representing the plaintext
  @param output: vector of hex values representing ciphertext (with padding)
  @param key: vector of hex values representing key to use
  @param nonce: a NUM_BYTES/2 (8) byte random block for the counter
  @return none
*/
void encrypt_ctr(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::array<unsigned char, NUM_BYTES / 2> &nonce) {
    // Calculate padding length, then copy input array and padding into plaintext
    const std::size_t inputSize = input.size();
    const std::size_t padLength = 16 - (inputSize % 16);
    const std::size_t plaintextLength = inputSize + padLength;

    // Plaintext accommodates both the input and the necessary padding
    std::vector<unsigned char> plaintext;
    plaintext.reserve(plaintextLength);
    plaintext = input;

    // TODO: investigate whether PKCS#7 is the best choice for padding (padding oracle attack)
    for (std::size_t i = 0; i < padLength; i++) {
        // PKCS#7 padding (source: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
        plaintext[inputSize + i] = padLength;
    }

    std::array<unsigned char, NUM_BYTES> counter{};
    counter.fill(0);
    std::copy(nonce.begin(), nonce.end(), counter.begin());

    std::array<unsigned char, NUM_BYTES> outputBlock;
    outputBlock.fill(0);

    for (std::size_t i = 0; i < plaintextLength / 16; i++) {
        std::cout << std::endl;
        //Encrypt the counter
        encrypt(counter, outputBlock, key);

        //XOR output with the plaintext and put into output block
        for (std::size_t j = 0; j < 16; j++) {
            output.push_back(plaintext[j + (i * 16)] ^ outputBlock[j]);
        }

        incrementCounter(counter, NUM_BYTES / 2);
    }

    printEncryptOutput(output);
}

/**
  inverse cipher with CTR mode
  @param input: vector of hex values representing the ciphertext (with padding)
  @param output: vector of hex values representing plaintext (without padding)
  @param key: vector of hex values representing key to use
  @param nonce: a NUM_BYTES/2 (8) byte random block for the counter
  @return none
*/
void decrypt_ctr(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::array<unsigned char, NUM_BYTES / 2> &nonce) {
    const std::size_t inputSize = input.size();

    std::array<unsigned char, NUM_BYTES> counter{};
    counter.fill(0);
    std::copy(nonce.begin(), nonce.end(), counter.begin());

    std::array<unsigned char, NUM_BYTES> outputBlock;
    outputBlock.fill(0);

    for (std::size_t i = 0; i < inputSize / 16; i++) {
        std::cout << std::endl;
        //Encrypt the counter
        encrypt(counter, outputBlock, key);

        //XOR output with the plaintext and put into output block
        for (std::size_t j = 0; j < 16; j++) {
            output.push_back(input[j + (i * 16)] ^ outputBlock[j]);
        }

        incrementCounter(counter, NUM_BYTES / 2);
    }

    // Remove padding
    const int lastByte = (int) output.back();
    output.erase(output.end() - lastByte, output.end());

    printDecryptOutput(output);
}

// TODO: input, output, key, should be set in main file and passed to each AES___.cpp file
int main() {
    // TODO: hardcoding IV=key here temporarily, but the IV and key should really be taken independently from AESRand
//  const std::array<unsigned char, NUM_BYTES> IV = {
//    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
//  };
    const std::vector<unsigned char> key = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    const std::array<unsigned char, NUM_BYTES / 2> IV = {
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7
    };
//  const std::vector<unsigned char> key = {
//    0x2b,0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
//  };
    std::vector<unsigned char> output;

    // UNCOMMENT BELOW TO TEST ENCRYPT_ECB
    // std::vector<unsigned char> input = {
    //   0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    // };
    // encrypt_ecb(input, output, key);

    // UNCOMMENT BELOW TO TEST DECRYPT_ECB
    // std::vector<unsigned char> input = { // vector, not array, because pad leads to variable sizes that are multiples of 16
    //   0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
    //   0x95, 0x4f, 0x64, 0xf2, 0xe4, 0xe8, 0x6e, 0x9e, 0xee, 0x82, 0xd2, 0x02, 0x16, 0x68, 0x48, 0x99
    // };
    // decrypt_ecb(input, output, key);

    ///////////////////////////////////////

    // UNCOMMENT BELOW TO TEST ENCRYPT_CBC
//  std::vector<unsigned char> input = {
//    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
//  }; // ENCRYPT TEST INPUT #1
//  encrypt_cbc(input, output, key, IV);

    // UNCOMMENT BELOW TO TEST DECRYPT_CBC
    std::vector<unsigned char> input = { // vector, not array, because pad leads to variable sizes that are multiples of 16
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    // decrypt_cbc(input, output, key, IV);

    encrypt_ctr(input, output, key, IV);

    input.clear();

    decrypt_ctr(output, input, key, IV);
}