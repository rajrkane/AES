/**
  @file AESmodes.cpp
  Implementation of ECB and CBC modes of operation for AES-128
*/
#include "AESmodes.hpp"
#include <iostream>

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
        // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
        const std::size_t inputSize = input.size();
        const std::size_t padLength = NUM_BYTES - (inputSize % NUM_BYTES);
        const std::size_t plaintextLength = inputSize + padLength;

        // Plaintext accommodates both the input and the necessary padding
        std::vector<unsigned char> plaintext;
        // Secure coding: OOP57-CPP. Prefer special member functions and overloaded operators to C Standard Library functions
        plaintext.reserve(plaintextLength);
        plaintext = input;


        for (std::size_t i = 0; i < padLength; i++) {
            // PKCS#7 padding (source: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
            plaintext.push_back(padLength);
        }


        // Loop over number of blocks
        for (std::size_t i = 0; i < plaintextLength / NUM_BYTES; i++) {

            // Loop over block size and fill each block
            std::array<unsigned char, NUM_BYTES> block{0};
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Using .at instead of [] for internal bounds checking, see CTR50-CPP
                block.at(j) = plaintext.at(j + (i * NUM_BYTES));
            }

            // Encrypt each block
            std::array<unsigned char, NUM_BYTES> outputBlock{};

            encrypt(block, outputBlock, key);

            // Copy encrypted block to the output
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                output.push_back(outputBlock.at(j));
            }
        }

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
        for (std::size_t i = 0; i < inputSize / NUM_BYTES; i++) {

            // Loop over block size and fill each block
            std::array<unsigned char, NUM_BYTES> block{0};
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                block.at(j) = input.at(j + (i * NUM_BYTES));
            }

            // Decrypt each block
            std::array<unsigned char, NUM_BYTES> outputPadded{0};
            decrypt(block, outputPadded, key);

            // Copy decrypted block to the output
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                output.push_back(outputPadded.at(j));
            }
        }

        if (!remove_padding(output)) {
            std::cout << "Decryption Error" << std::endl;
            //Erase the output to avoid any other information leaking
            output.clear();
            return false;
        }

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
        const std::size_t padLength = NUM_BYTES - (inputSize % NUM_BYTES);
        const std::size_t plaintextLength = inputSize + padLength;

        //std::cout << std::hex << inputSize << std::endl;

        // Plaintext accommodates both the input and the necessary padding
        std::vector<unsigned char> plaintext;
        plaintext.reserve(plaintextLength);
        plaintext = input;

        for (std::size_t i = 0; i < padLength; i++) {
            // PKCS#7 padding (source: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
            plaintext.push_back(padLength);
        }

        // Encrypt the first block
        std::array<unsigned char, NUM_BYTES> block{0};
        for (std::size_t j = 0; j < NUM_BYTES; j++) {
            // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
            block.at(j) = plaintext.at(j) ^ IV.at(j);
        }

        std::array<unsigned char, NUM_BYTES> outputBlock{0};
        encrypt(block, outputBlock, key);

        for (std::size_t j = 0; j < NUM_BYTES; j++) {
            // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
            output.push_back(outputBlock.at(j));
        }

        // Loop over the number of subsequent blocks
        for (std::size_t i = 1; i < plaintextLength / NUM_BYTES; i++) {
            // Loop over block size and fill each block
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                block.at(j) = plaintext.at(j + (i * NUM_BYTES)) ^ output.at(j + ((i - 1) * NUM_BYTES));
            }

            // Encrypt each block
            encrypt(block, outputBlock, key);

            // Copy encrypted block to the output
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                output.push_back(outputBlock.at(j));
            }
        }

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
        std::array<unsigned char, NUM_BYTES> block{0};
        for (std::size_t i = 0; i < NUM_BYTES; i++) {
            // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
            block.at(i) = input.at(i);
        }

        std::array<unsigned char, NUM_BYTES> outputPadded{0};
        decrypt(block, outputPadded, key);

        for (std::size_t i = 0; i < NUM_BYTES; i++) {
            // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
            outputPadded.at(i) ^= IV.at(i);
            output.push_back(outputPadded.at(i));
        }

        // Loop over the number of subsequent blocks
        for (std::size_t i = 1; i < inputSize / NUM_BYTES; i++) {

            // Loop over block size and fill each block
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                block.at(j) = input.at(j + (i * NUM_BYTES));
            }

            // Decrypt each block
            decrypt(block, outputPadded, key);

            // Copy decrypted block to the output
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                outputPadded.at(j) ^= input.at(j + ((i - 1) * NUM_BYTES));
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
        // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
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
        const std::size_t padLength = NUM_BYTES - (inputSize % NUM_BYTES);
        const std::size_t plaintextLength = inputSize + padLength;

        // Plaintext accommodates both the input and the necessary padding
        std::vector<unsigned char> plaintext;
        plaintext.reserve(plaintextLength);
        plaintext = input;

        for (std::size_t i = 0; i < padLength; i++) {
            // PKCS#7 padding (source: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
            plaintext.push_back(padLength);
        }

        std::array<unsigned char, NUM_BYTES> counter{0};
        counter.fill(0);
        std::copy(nonce.begin(), nonce.end(), counter.begin());

        std::array<unsigned char, NUM_BYTES> outputBlock{0};
        outputBlock.fill(0);

        for (std::size_t i = 0; i < plaintextLength / NUM_BYTES; i++) {
            //Encrypt the counter
            encrypt(counter, outputBlock, key);

            //XOR output with the plaintext and put into output block
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                output.push_back(plaintext.at(j + (i * NUM_BYTES)) ^ outputBlock.at(j));
            }

            incrementCounter(counter, NUM_BYTES / 2);
        }

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

        std::array<unsigned char, NUM_BYTES> counter{0};
        // Secure coding: OOP57-CPP. Prefer special member functions and overloaded operators to C Standard Library functions
        counter.fill(0);
        std::copy(nonce.begin(), nonce.end(), counter.begin());

        std::array<unsigned char, NUM_BYTES> outputBlock{0};
        // Secure coding: OOP57-CPP. Prefer special member functions and overloaded operators to C Standard Library functions
        outputBlock.fill(0);

        for (std::size_t i = 0; i < inputSize / NUM_BYTES; i++) {
            //Encrypt the counter
            encrypt(counter, outputBlock, key);

            //XOR output with the plaintext and put into output block
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                output.push_back(input.at(j + (i * NUM_BYTES)) ^ outputBlock.at(j));
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
        const std::size_t padLength = NUM_BYTES - (inputSize % NUM_BYTES);
        const std::size_t plaintextLength = inputSize + padLength;

        // Plaintext accomodates both the input and the necessary padding
        std::vector<unsigned char> plaintext;
        plaintext.reserve(plaintextLength);
        plaintext = input;

        for (std::size_t i = 0; i < padLength; i++) {
            // PKCS#7 padding (source: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
            plaintext.push_back(padLength);
        }

        // Encrypt the first block
        std::array<unsigned char, NUM_BYTES> block{0};
        std::array<unsigned char, NUM_BYTES> outputBlock{0};

        std::copy(IV.begin(), IV.end(), block.begin());

        encrypt(block, outputBlock, key);

        for (std::size_t j = 0; j < NUM_BYTES; j++) {
            // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
            output.push_back(outputBlock.at(j) ^ plaintext.at(j));
        }

        // Loop over the number of subsequent blocks
        for (std::size_t i = 1; i < plaintextLength / NUM_BYTES; i++) {
            // Loop over block size and fill each block
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                block.at(j) = output.at(j + ((i - 1) * NUM_BYTES));
            }

            // Encrypt each block
            encrypt(block, outputBlock, key);

            // Copy encrypted block to the output
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                output.push_back(outputBlock.at(j) ^ plaintext.at(j + (i * NUM_BYTES)));
            }
        }

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
        std::array<unsigned char, NUM_BYTES> block{0};
        std::array<unsigned char, NUM_BYTES> outputBlock{0};

        // Secure coding: OOP57-CPP. Prefer special member functions and overloaded operators to C Standard Library functions
        std::copy(IV.begin(), IV.end(), block.begin());

        encrypt(block, outputBlock, key);

        for (std::size_t j = 0; j < NUM_BYTES; j++) {
            // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
            output.push_back(outputBlock.at(j) ^ input.at(j));
        }

        // Loop over the number of subsequent blocks
        for (std::size_t i = 1; i < inputSize / NUM_BYTES; i++) {
            // Loop over block size and fill each block
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                block.at(j) = input.at(j + ((i - 1) * NUM_BYTES));
            }

            // Encrypt each block
            encrypt(block, outputBlock, key);

            // Copy encrypted block to the output
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                output.push_back(outputBlock.at(j) ^ input.at(j + (i * NUM_BYTES)));
            }
        }
        // Remove padding
        if (!remove_padding(output)) {
            std::cout << "Decryption Error" << std::endl;
            //Erase the output to avoid any other information leaking
            output.clear();
            return false;
        }

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
        const std::size_t padLength = NUM_BYTES - (inputSize % NUM_BYTES);
        const std::size_t plaintextLength = inputSize + padLength;

        // Plaintext accommodates both the input and the necessary padding
        std::vector<unsigned char> plaintext;
        plaintext.reserve(plaintextLength);
        plaintext = input;

        for (std::size_t i = 0; i < padLength; i++) {
            // PKCS#7 padding (source: https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
            plaintext.push_back(padLength);
        }

        // Encrypt the first block
        std::array<unsigned char, NUM_BYTES> block{0};
        std::array<unsigned char, NUM_BYTES> outputBlock{0};

        // Secure coding: OOP57-CPP. Prefer special member functions and overloaded operators to C Standard Library functions
        std::copy(IV.begin(), IV.end(), block.begin());

        encrypt(block, outputBlock, key);

        for (std::size_t j = 0; j < NUM_BYTES; j++) {
            // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
            output.push_back(outputBlock.at(j) ^ plaintext.at(j));
        }

        // Loop over the number of subsequent blocks
        for (std::size_t i = 1; i < plaintextLength / NUM_BYTES; i++) {
            // Loop over block size and fill each block
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                block.at(j) = outputBlock.at(j);
            }

            // Encrypt each block
            encrypt(block, outputBlock, key);

            // Copy encrypted block to the output
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                output.push_back(outputBlock.at(j) ^ plaintext.at(j + (i * NUM_BYTES)));
            }
        }

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
        std::array<unsigned char, NUM_BYTES> block{0};
        std::array<unsigned char, NUM_BYTES> outputBlock{0};

        // Secure coding: OOP57-CPP. Prefer special member functions and overloaded operators to C Standard Library functions
        std::copy(IV.begin(), IV.end(), block.begin());

        encrypt(block, outputBlock, key);

        for (std::size_t j = 0; j < NUM_BYTES; j++) {
            // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
            output.push_back(outputBlock.at(j) ^ input.at(j));
        }

        // Loop over the number of subsequent blocks
        for (std::size_t i = 1; i < inputSize / NUM_BYTES; i++) {
            // Loop over block size and fill each block
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                block.at(j) = outputBlock.at(j);
            }

            // Encrypt each block
            encrypt(block, outputBlock, key);

            // Copy encrypted block to the output
            for (std::size_t j = 0; j < NUM_BYTES; j++) {
                // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
                output.push_back(outputBlock.at(j) ^ input.at(j + (i * NUM_BYTES)));
            }
        }
        // Remove padding
        if (!remove_padding(output)) {
            std::cout << "Decryption Error" << std::endl;
            //Erase the output to avoid any other information leaking
            output.clear();
            return false;
        }
    } catch (std::exception &e) {
        //Catch exception by lvalue or reference per ERR61-CPP
        std::cout << "Decryption Error" << std::endl;
        output.clear();
        return false;
    }

    return true;
}