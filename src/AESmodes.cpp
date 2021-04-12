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

bool remove_padding(std::vector<unsigned char> &input) noexcept(false) {
    const int lastByte = (int) input.back();
    //Only continue if the last byte is in the valid range
    if (lastByte <= NUM_BYTES && lastByte > 0) {
        //Verify that the padding is okay
        for (std::size_t i = 0; i < lastByte; i++) {
            if (input.at(input.size() - i - 1) != lastByte)
                //Do nothing and return
                return false;
        }
        input.erase(input.end() - lastByte, input.end());
        return true;
    }
    //If an improper padding value was given, also do nothing
    //TODO: I don't know for sure if this resolves the padding oracle attack, I'll look into it some more
    return false;
}

/**
  Cipher with ECB mode
  Guaranteed no exceptions by:
    handling all exceptions per ERR51-CPP
        Related: Honoring exception specifications, all exceptions will be caught per ERR55-CPP
    not throwing exceptions across execution boundaries (library to application) per ERR59-CPP
    Guaranteeing Strong exception safety per ERR56-CPP
        Program state will not be modified
            Input and key are constant and output vector is cleared when catching an exception
  @param input: vector of hex values representing plaintext
  @param output: vector of hex values representing (padded) ciphertext
  @param key: vector of hex values representing key to use
  @return True on success
*/
bool encrypt_ecb(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key) noexcept(true) {
    try {
        // Calculate padding length, then copy input array and padding into plaintext
        const std::size_t inputSize = input.size();
        const std::size_t padLength = 16 - (inputSize % 16);
        const std::size_t plaintextLength = inputSize + padLength;

        // Plaintext accommodates both the input and the necessary padding
        std::vector<unsigned char> plaintext;
        plaintext = input;
        plaintext.reserve(plaintextLength);

        // TODO: ECB and CBC both repeat this code for padding. Cleaner for padding to have its own function
        for (std::size_t i = 0; i < padLength; i++) {
            // PKCS#7 padding (source: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
            plaintext.push_back(padLength);
        }


        // Loop over number of blocks
        for (std::size_t i = 0; i < plaintextLength / 16; i++) {

            // Loop over block size and fill each block
            std::array<unsigned char, 16> block;
            for (std::size_t j = 0; j < 16; j++) {
                // Using .at instead of [] for internal bounds checking, see CTR50-CPP
                block.at(j) = plaintext.at(j + (i * 16));
            }

            // Encrypt each block
            std::array<unsigned char, 16> outputBlock;
            encrypt(block, outputBlock, key); // TODO: this is sequential, and could be parallelized

            // Copy encrypted block to the output
            for (std::size_t j = 0; j < 16; j++) {
                output.push_back(outputBlock.at(j));
            }
        }

        printEncryptOutput(output);

    } catch (std::exception &e) {
        //Catch exception by lvalue or reference per ERR61-CPP
        std::cout << "Encryption Error" << std::endl;
        output.clear();
        return false;
    }
    return true;
}


/**
  Inverse cipher with ECB mode
  Guaranteed no exceptions by:
    handling all exceptions per ERR51-CPP
        Related: Honoring exception specifications, all exceptions will be caught per ERR55-CPP
    not throwing exceptions across execution boundaries (library to application) per ERR59-CPP
    Guaranteeing Strong exception safety per ERR56-CPP
        Program state will not be modified
            Input and key are constant and output vector is cleared when catching an exception
  @param input: vector of hex values representing (padded) ciphertext
  @param output: vector of hex values representing plaintext (without padding)
  @param key: vector of hex values representing key to use
  @return True on success
*/
bool decrypt_ecb(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key) noexcept(true) {
    try {
        const std::size_t inputSize = input.size();

        // Loop over number of blocks
        for (std::size_t i = 0; i < inputSize / 16; i++) {

            // Loop over block size and fill each block
            std::array<unsigned char, 16> block;
            for (std::size_t j = 0; j < 16; j++) {
                block.at(j) = input.at(j + (i * 16));
            }

            // Decrypt each block
            std::array<unsigned char, 16> outputPadded;
            decrypt(block, outputPadded, key);

            // Copy decrypted block to the output
            for (std::size_t j = 0; j < 16; j++) {
                output.push_back(outputPadded.at(j));
            }
        }

//    const int lastByte = (int) output.back();
//    output.erase(output.end() - lastByte, output.end()); // Padding value is also the padding length

        if (!remove_padding(output)) {
            std::cout << "Decryption Error" << std::endl;
            //Erase the output to avoid any other information leaking
            output.clear();
            return false;
        }

        printDecryptOutput(output);
    } catch (std::exception &e) {
        //Catch exception by lvalue or reference per ERR61-CPP
        std::cout << "Decryption Error" << std::endl;
        output.clear();
        return false;
    }

    return true;

}


/**
  Cipher with CBC mode
  Guaranteed no exceptions by:
    handling all exceptions per ERR51-CPP
        Related: Honoring exception specifications, all exceptions will be caught per ERR55-CPP
    not throwing exceptions across execution boundaries (library to application) per ERR59-CPP
    Guaranteeing Strong exception safety per ERR56-CPP
        Program state will not be modified
            Input, key, and IV are constant and output vector is cleared when catching an exception
  @param input: vector of hex values representing plaintext
  @param output: vector of hex values representing (padded) ciphertext
  @param key: vector of hex values representing key to use
  @param IV: initialization vector to use
  @return True on success
*/
bool encrypt_cbc(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) noexcept(true) {
    try {
        // Calculate padding length, then copy input array and padding into plaintext
        const std::size_t inputSize = input.size();
        const std::size_t padLength = 16 - (inputSize % 16);
        const std::size_t plaintextLength = inputSize + padLength;

        //std::cout << std::hex << inputSize << std::endl;

        // Plaintext accommodates both the input and the necessary padding
        std::vector<unsigned char> plaintext;
        plaintext.reserve(plaintextLength);
        plaintext = input;

        // TODO: investigate whether PKCS#7 is the best choice for padding (padding oracle attack)
        for (std::size_t i = 0; i < padLength; i++) {
            // PKCS#7 padding (source: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
            plaintext.push_back(padLength);
        }

        // Encrypt the first block
        std::array<unsigned char, 16> block;
        for (std::size_t j = 0; j < 16; j++) {
            block.at(j) = plaintext.at(j) ^ IV.at(j);
        }

        std::array<unsigned char, 16> outputBlock;
        encrypt(block, outputBlock, key);

        for (std::size_t j = 0; j < 16; j++) {
            output.push_back(outputBlock.at(j));
        }

        // Loop over the number of subsequent blocks
        for (std::size_t i = 1; i < plaintextLength / 16; i++) {
            // Loop over block size and fill each block
            for (std::size_t j = 0; j < 16; j++) {
                //std::cout << std::hex << (int) plaintext[j + (i * 16)] << ' ';
                block.at(j) = plaintext.at(j + (i * 16)) ^ output.at(j + ((i - 1) * 16));
            }

            //std::cout << std::endl;

            // Encrypt each block
            encrypt(block, outputBlock, key);

            // Copy encrypted block to the output
            for (std::size_t j = 0; j < 16; j++) {
                output.push_back(outputBlock.at(j));
            }
        }

        printEncryptOutput(output);
    } catch (std::exception &e) {
        //Catch exception by lvalue or reference per ERR61-CPP
        std::cout << "Encryption Error" << std::endl;
        output.clear();
        return false;
    }
    return true;
}


/**
  Inverse cipher with CBC mode
    Guaranteed no exceptions by:
    handling all exceptions per ERR51-CPP
        Related: Honoring exception specifications, all exceptions will be caught per ERR55-CPP
    not throwing exceptions across execution boundaries (library to application) per ERR59-CPP
    Guaranteeing Strong exception safety per ERR56-CPP
        Program state will not be modified
            Input, key, and IV are constant and output vector is cleared when catching an exception
  @param input: vector of hex values representing (padded) ciphertext
  @param output: vector of hex values representing plaintext (without padding)
  @param key: vector of hex values representing key to use
  @param IV: initialization vector to use
  @return True on success
*/
bool decrypt_cbc(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) noexcept(true) {
    try {


        const std::size_t inputSize = input.size();

        // Decrypt the first block
        std::array<unsigned char, 16> block;
        for (std::size_t i = 0; i < 16; i++) {
            block.at(i) = input.at(i);
        }

        std::array<unsigned char, 16> outputPadded;
        decrypt(block, outputPadded, key);

        for (std::size_t i = 0; i < 16; i++) {
            outputPadded.at(i) ^= IV.at(i);
            output.push_back(outputPadded.at(i));
        }

        // Loop over the number of subsequent blocks
        for (std::size_t i = 1; i < inputSize / 16; i++) {

            // Loop over block size and fill each block
            for (std::size_t j = 0; j < 16; j++) {
                block.at(j) = input.at(j + (i * 16));
            }

            // Decrypt each block
            decrypt(block, outputPadded, key);

            // Copy decrypted block to the output
            for (std::size_t j = 0; j < 16; j++) {
                outputPadded.at(j) ^= input.at(j + ((i - 1) * 16));
                output.push_back(outputPadded.at(j));
            }
        }


        // Remove padding
        if (!remove_padding(output)) {
            std::cout << "Decryption Error" << std::endl;
            //Erase the output to avoid any other information leaking
            output.clear();
            return false;
        }

        printDecryptOutput(output);
    } catch (std::exception &e) {
        //Catch exception by lvalue or reference per ERR61-CPP
        std::cout << "Decryption Error" << std::endl;
        output.clear();
        return false;
    }
    return true;

}

/**
  increments the counter block by one
  @param counter: array of values containing a nonce and a counter section
  @param numCounterBytes: the number of bytes in the counter array that are actually part of the counter
  @return none
*/
void incrementCounter(std::array<unsigned char, NUM_BYTES> &counter, int numCounterBytes) noexcept(false) {
    for (int i = NUM_BYTES - 1; i >= numCounterBytes; i--) {
        //Increment the current byte
        counter.at(i) = counter.at(i) + 1;
        //If the byte did not overflow to zero, then stop
        //Otherwise continue until an overflow does not happen
        if (counter.at(i) != 0)
            break;
    }
}

/**
  cipher with CTR mode
    Guaranteed no exceptions by:
    handling all exceptions per ERR51-CPP
        Related: Honoring exception specifications, all exceptions will be caught per ERR55-CPP
    not throwing exceptions across execution boundaries (library to application) per ERR59-CPP
    Guaranteeing Strong exception safety per ERR56-CPP
        Program state will not be modified
            Input, key, and nonce are constant and output vector is cleared when catching an exception
  @param input: vector of hex values representing the plaintext
  @param output: vector of hex values representing ciphertext (with padding)
  @param key: vector of hex values representing key to use
  @param nonce: a NUM_BYTES/2 (8) byte random block for the counter
  @return True on success
*/
bool encrypt_ctr(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key,
                 const std::array<unsigned char, NUM_BYTES / 2> &nonce) noexcept(true) {
    try {
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
            plaintext.push_back(padLength);
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
                output.push_back(plaintext.at(j + (i * 16)) ^ outputBlock.at(j));
            }

            incrementCounter(counter, NUM_BYTES / 2);
        }

        printEncryptOutput(output);
    } catch (std::exception &e) {
        //Catch exception by lvalue or reference per ERR61-CPP
        std::cout << "Encryption Error" << std::endl;
        output.clear();
        return false;
    }
    return true;

}

/**
  inverse cipher with CTR mode
    Guaranteed no exceptions by:
    handling all exceptions per ERR51-CPP
        Related: Honoring exception specifications, all exceptions will be caught per ERR55-CPP
    not throwing exceptions across execution boundaries (library to application) per ERR59-CPP
    Guaranteeing Strong exception safety per ERR56-CPP
        Program state will not be modified
            Input, key, and nonce are constant and output vector is cleared when catching an exception
  @param input: vector of hex values representing the ciphertext (with padding)
  @param output: vector of hex values representing plaintext (without padding)
  @param key: vector of hex values representing key to use
  @param nonce: a NUM_BYTES/2 (8) byte random block for the counter
  @return True on success
*/
bool decrypt_ctr(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key,
                 const std::array<unsigned char, NUM_BYTES / 2> &nonce) noexcept(true) {
    try {

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
                output.push_back(input.at(j + (i * 16)) ^ outputBlock.at(j));
            }

            incrementCounter(counter, NUM_BYTES / 2);
        }

        // Remove padding
        if (!remove_padding(output)) {
            std::cout << "Decryption Error" << std::endl;
            //Erase the output to avoid any other information leaking
            output.clear();
            return false;
        }

        printDecryptOutput(output);
    } catch (std::exception &e) {
        //Catch exception by lvalue or reference per ERR61-CPP
        std::cout << "Decryption Error" << std::endl;
        output.clear();
        return false;
    }
    return true;
}

/**
  Cipher with CFB128 mode
    Guaranteed no exceptions by:
    handling all exceptions per ERR51-CPP
        Related: Honoring exception specifications, all exceptions will be caught per ERR55-CPP
    not throwing exceptions across execution boundaries (library to application) per ERR59-CPP
    Guaranteeing Strong exception safety per ERR56-CPP
        Program state will not be modified
            Input, key, and IV are constant and output vector is cleared when catching an exception
  @param input: vector of hex values representing plaintext
  @param output: vector of hex values representing (padded) ciphertext
  @param key: vector of hex values representing key to use
  @param IV: initialization vector to use
  @return True on success
*/
bool encrypt_cfb(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) noexcept(true) {
    try {

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
            plaintext.push_back(padLength);
        }

        // Encrypt the first block
        std::array<unsigned char, 16> block;
        std::array<unsigned char, 16> outputBlock;

        std::copy(IV.begin(), IV.end(), block.begin());

        encrypt(block, outputBlock, key);

        for (std::size_t j = 0; j < 16; j++) {
            output.push_back(outputBlock.at(j) ^ plaintext.at(j));
        }

        // Loop over the number of subsequent blocks
        for (std::size_t i = 1; i < plaintextLength / 16; i++) {
            // Loop over block size and fill each block
            for (std::size_t j = 0; j < 16; j++) {
                block.at(j) = output.at(j + ((i - 1) * 16));
            }

            // Encrypt each block
            encrypt(block, outputBlock, key);

            // Copy encrypted block to the output
            for (std::size_t j = 0; j < 16; j++) {
                output.push_back(outputBlock.at(j) ^ plaintext.at(j + (i * 16)));
            }
        }

        printEncryptOutput(output);
    } catch (std::exception &e) {
        //Catch exception by lvalue or reference per ERR61-CPP
        std::cout << "Encryption Error" << std::endl;
        output.clear();
        return false;
    }
    return true;
}

/**
  Inverse cipher with CFB128 mode
    Guaranteed no exceptions by:
    handling all exceptions per ERR51-CPP
        Related: Honoring exception specifications, all exceptions will be caught per ERR55-CPP
    not throwing exceptions across execution boundaries (library to application) per ERR59-CPP
    Guaranteeing Strong exception safety per ERR56-CPP
        Program state will not be modified
            Input, key, and IV are constant and output vector is cleared when catching an exception
  @param input: vector of hex values representing (padded) ciphertext
  @param output: vector of hex values representing plaintext (without padding)
  @param key: vector of hex values representing key to use
  @param IV: initialization vector to use
  @return True on success
*/
bool decrypt_cfb(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) noexcept(true) {
    try {

        const std::size_t inputSize = input.size();

        // Encrypt the first block
        std::array<unsigned char, 16> block;
        std::array<unsigned char, 16> outputBlock;

        std::copy(IV.begin(), IV.end(), block.begin());

        encrypt(block, outputBlock, key);

        for (std::size_t j = 0; j < 16; j++) {
            output.push_back(outputBlock.at(j) ^ input.at(j));
        }

        // Loop over the number of subsequent blocks
        for (std::size_t i = 1; i < inputSize / 16; i++) {
            // Loop over block size and fill each block
            for (std::size_t j = 0; j < 16; j++) {
                block.at(j) = input.at(j + ((i - 1) * 16));
            }

            // Encrypt each block
            encrypt(block, outputBlock, key);

            // Copy encrypted block to the output
            for (std::size_t j = 0; j < 16; j++) {
                output.push_back(outputBlock.at(j) ^ input.at(j + (i * 16)));
            }
        }
        // Remove padding
        if (!remove_padding(output)) {
            std::cout << "Decryption Error" << std::endl;
            //Erase the output to avoid any other information leaking
            output.clear();
            return false;
        }

        printDecryptOutput(output);
    } catch (std::exception &e) {
        //Catch exception by lvalue or reference per ERR61-CPP
        std::cout << "Decryption Error" << std::endl;
        output.clear();
        return false;
    }
    return true;
}

/**
  Cipher with OFB mode
    Guaranteed no exceptions by:
    handling all exceptions per ERR51-CPP
        Related: Honoring exception specifications, all exceptions will be caught per ERR55-CPP
    not throwing exceptions across execution boundaries (library to application) per ERR59-CPP
    Guaranteeing Strong exception safety per ERR56-CPP
        Program state will not be modified
            Input, key, and IV are constant and output vector is cleared when catching an exception
  @param input: vector of hex values representing plaintext
  @param output: vector of hex values representing (padded) ciphertext
  @param key: vector of hex values representing key to use
  @param IV: initialization vector to use
  @return True on success
*/
bool encrypt_ofb(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) noexcept(true) {
    try {

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
            plaintext.push_back(padLength);
        }

        // Encrypt the first block
        std::array<unsigned char, 16> block;
        std::array<unsigned char, 16> outputBlock;

        std::copy(IV.begin(), IV.end(), block.begin());

        encrypt(block, outputBlock, key);

        for (std::size_t j = 0; j < 16; j++) {
            output.push_back(outputBlock.at(j) ^ plaintext.at(j));
        }

        // Loop over the number of subsequent blocks
        for (std::size_t i = 1; i < plaintextLength / 16; i++) {
            // Loop over block size and fill each block
            for (std::size_t j = 0; j < 16; j++) {
                block.at(j) = outputBlock.at(j);
            }

            // Encrypt each block
            encrypt(block, outputBlock, key);

            // Copy encrypted block to the output
            for (std::size_t j = 0; j < 16; j++) {
                output.push_back(outputBlock.at(j) ^ plaintext.at(j + (i * 16)));
            }
        }

        printEncryptOutput(output);
    } catch (std::exception &e) {
        //Catch exception by lvalue or reference per ERR61-CPP
        std::cout << "Encryption Error" << std::endl;
        output.clear();

        return false;
    }
    return true;
}

/**
  Inverse cipher with OFB mode
    Guaranteed no exceptions by:
    handling all exceptions per ERR51-CPP
        Related: Honoring exception specifications, all exceptions will be caught per ERR55-CPP
    not throwing exceptions across execution boundaries (library to application) per ERR59-CPP
    Guaranteeing Strong exception safety per ERR56-CPP
        Program state will not be modified
            Input, key, and IV are constant and output vector is cleared when catching an exception
  @param input: vector of hex values representing (padded) ciphertext
  @param output: vector of hex values representing plaintext (without padding)
  @param key: vector of hex values representing key to use
  @param IV: initialization vector to use
  @return True on success
*/
bool decrypt_ofb(const std::vector<unsigned char> &input, std::vector<unsigned char> &output,
                 const std::vector<unsigned char> &key, const std::vector<unsigned char> &IV) noexcept(true) {
    try {

        const std::size_t inputSize = input.size();

        // Encrypt the first block
        std::array<unsigned char, 16> block;
        std::array<unsigned char, 16> outputBlock;

        std::copy(IV.begin(), IV.end(), block.begin());

        encrypt(block, outputBlock, key);

        for (std::size_t j = 0; j < 16; j++) {
            output.push_back(outputBlock.at(j) ^ input.at(j));
        }

        // Loop over the number of subsequent blocks
        for (std::size_t i = 1; i < inputSize / 16; i++) {
            // Loop over block size and fill each block
            for (std::size_t j = 0; j < 16; j++) {
                block.at(j) = outputBlock.at(j);
            }

            // Encrypt each block
            encrypt(block, outputBlock, key);

            // Copy encrypted block to the output
            for (std::size_t j = 0; j < 16; j++) {
                output.push_back(outputBlock.at(j) ^ input.at(j + (i * 16)));
            }
        }
        // Remove padding
        if (!remove_padding(output)) {
            std::cout << "Decryption Error" << std::endl;
            //Erase the output to avoid any other information leaking
            output.clear();
            return false;
        }

        printDecryptOutput(output);
    } catch (std::exception &e) {
        //Catch exception by lvalue or reference per ERR61-CPP
        std::cout << "Decryption Error" << std::endl;
        output.clear();
        return false;
    }

    return true;
}

// TODO: input, output, key, should be set in main file and passed to each AES___.cpp file
int main() {
    // TODO: hardcoding IV=key here temporarily, but the IV and key should really be taken independently from AESRand
    const std::vector<unsigned char> IV = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
//    const std::vector<unsigned char> key = {
//            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
//    };

//    const std::vector<unsigned char> IV = {
//            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7
//    };
    const std::vector<unsigned char> key = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
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
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };
    // decrypt_cbc(input, output, key, IV);

    encrypt_ecb(input, output, key);

    input.clear();

    decrypt_ecb(output, input, key);

    output.clear();

    encrypt_cbc(input, output, key, IV);

    input.clear();

    decrypt_cbc(output, input, key, IV);

    output.clear();

    encrypt_cfb(input, output, key, IV);

    input.clear();

    decrypt_cfb(output, input, key, IV);

    output.clear();

    encrypt_ofb(input, output, key, IV);

    input.clear();

    decrypt_ofb(output, input, key, IV);
}