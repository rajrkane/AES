/**
  @file AESmodes.cpp
  Implementation of user interface with the program
*/

#include <iostream>
#include <string>
#include <algorithm>
#include <cstring>
#include "AESRand.hpp"
#include "AESmodes.hpp"
#include "encrypt.hpp"
#include "decrypt.hpp"
#include "interface.hpp"


// USAGE: ./main [enc, encrypt/ dec, decrypt] [ecb/cbc/cfb/ofb/ctr] [-r/-k] [128, 192, 256] (-iv/-nonce)

// [] - required parameters*
// () - optional parameters
// *[-r/-k] omitted for decryption

int main(int argc, char** argv) {
    AESRand rand;
    std::vector<unsigned char> input;
    std::vector<unsigned char> output;
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;

    const int IV_SIZE = 16;
    std::string line;
    unsigned char char_iterator;

    bool algorithmSuccess;

    if(argc >= 4) {
        char* aes_function = argv[1];
        char* mode = argv[2];
        char* keyType = argv[3];


        // Encryption
        if (std::strcmp(aes_function, "encrypt") == 0 || std::strcmp(aes_function, "enc") == 0) {
            char* keySize;
            int keyByteSize;
            // Extract key size from command line arguments if proper number of arguments provided
            if (argc > 4) {
                keySize = argv[4];
                // Convert key size to integer value
                keyByteSize = getKeySizeInBytes(keySize);
            }
            else {
                // Invalid number of arguments to extract key size
                keyByteSize = -1;
            }

            // If invalid key size is entered, output error message and terminate program
            if (keyByteSize == -1) {
                std::cout << "Invalid parameter for key size.\n";
                return 2;
            }

            // Receive plaintext to encrypt
            std::cout << "Enter plaintext: ";

            inputToVector(input);

            // Create random key if -r command line argument is provided
            if (std::strcmp(keyType, "-r") == 0) {
                key = rand.generateBytes(keyByteSize);
            }
            // Receive key from user input if -k command line argument is provided
            else if (std::strcmp(keyType, "-k") == 0) {
                std::cout << "Enter key: ";
                inputToVector(key);
                // Check that user entered correct number of bytes for designated key size
                if (key.size() != keyByteSize) {
                    std::cout << "Invalid number of bytes entered for key.\n";
                    return 2;
                }

            }
            // If no valid flag is provided, alert user and terminate execution
            else {
                std::cout << "Invalid flag entered for key\n";
                return 2;
            }

            // Encrypt with mode entered by user

            // Encryption with ECB
            if (std::strcmp(mode, "ecb") == 0 || std::strcmp(mode, "ECB") == 0) {
                algorithmSuccess = encrypt_ecb(input, output, key);

                // Stop execution if encryption is unsuccessful
                if (!algorithmSuccess)
                    return 3;

                printEncryptionResults(output, key);
            }
            // Encryption with CBC
            else if (std::strcmp(mode, "cbc") == 0 || std::strcmp(mode, "CBC") == 0) {
                // If -iv command line argument is provided, receive value of IV from user
                if (argc == 6 && std::strcmp(argv[5], "-iv") == 0) {
                    std::cout << "Enter IV: ";
                    inputToVector(iv);

                    // Ensure IV size is correct
                    if (iv.size() != NUM_BYTES) {
                        std::cout << "Invalid number of bytes entered for IV\n";
                        return 2;
                    }

                }
                else {
                    iv = rand.generateBytes(IV_SIZE);
                }
                algorithmSuccess = encrypt_cbc(input, output, key, iv);

                // Stop execution if encryption is unsuccessful
                if (!algorithmSuccess)
                    return 3;

                printEncryptionResults(output, key, iv);
            }
            // Encryption with CFB
            else if (std::strcmp(mode, "cfb") == 0 || std::strcmp(mode, "CFB") == 0) {
                // If -iv command line argument is provided, receive value of IV from user
                if (argc == 6 && std::strcmp(argv[5], "-iv") == 0) {
                    std::cout << "Enter IV: ";
                    inputToVector(iv);

                    // Ensure IV size is correct
                    if (iv.size() != NUM_BYTES) {
                        std::cout << "Invalid number of bytes entered for IV\n";
                        return 2;
                    }

                }
                else {
                    iv = rand.generateBytes(IV_SIZE);
                }

                algorithmSuccess = encrypt_cfb(input, output, key, iv);

                // Stop execution if encryption is unsuccessful
                if (!algorithmSuccess)
                    return 3;

                printEncryptionResults(output, key, iv);
            }
            // Encryption with OFB
            else if (std::strcmp(mode, "ofb") == 0 || std::strcmp(mode, "OFB") == 0) {
                // If -iv command line argument is provided, receive value of IV from user
                if (argc == 6 && std::strcmp(argv[5], "-iv") == 0) {
                    std::cout << "Enter IV: ";
                    inputToVector(iv);

                    // Ensure IV size is correct
                    if (iv.size() != NUM_BYTES) {
                        std::cout << "Invalid number of bytes entered for IV\n";
                        return 2;
                    }

                }
                else {
                    iv = rand.generateBytes(IV_SIZE);
                }

                algorithmSuccess = encrypt_ofb(input, output, key, iv);

                // Stop execution if encryption is unsuccessful
                if (!algorithmSuccess)
                    return 3;

                printEncryptionResults(output, key, iv);
            }
            // Encryption with CTR
            else if (std::strcmp(mode, "ctr") == 0 || std::strcmp(mode, "CTR") == 0) {
                std::array<unsigned char, NUM_BYTES / 2> nonce;
                std::vector<unsigned char> vectorNonce;

                // Set value of nonce
                // If -nonce command line argument is provided, receive value of nonce from user
                if (argc == 6 && std::strcmp(argv[5], "-nonce") == 0) {
                    std::cout << "Enter nonce: ";
                    inputToVector(vectorNonce);

                    if (vectorNonce.size() != NUM_BYTES / 2) {
                        std::cout << "Invalid number of bytes entered for nonce.\n";
                        return 4;
                    }

                    std::copy(vectorNonce.begin(), vectorNonce.end(), nonce.begin());
                }
                // If not for debugging, generate nonce value for encryption with CTR
                else {
                    vectorNonce = rand.generateBytes(NUM_BYTES / 2);
                    std::copy(vectorNonce.begin(), vectorNonce.end(), nonce.begin());
                }

                algorithmSuccess = encrypt_ctr(input, output, key, nonce);

                // Stop execution if encryption is unsuccessful
                if (!algorithmSuccess)
                    return 3;

                printEncryptionResults(output, key, nonce);
            }

        }

        // Decrypt functionality

        if (std::strcmp(argv[1], "decrypt") == 0 || std::strcmp(argv[1], "dec") == 0) {
            char* keySize = argv[3];

            int keyByteSize = getKeySizeInBytes(keySize);

            // If invalid key size is entered, output error message and terminate program
            if (keyByteSize == -1) {
                std::cout << "Invalid parameter for key size.\n";
                return 2;
            }


            // Receive ciphertext to decrypt
            std::cout << "Enter ciphertext: ";
            inputToVector(input);

            // Receive key
            std::cout << "Enter key: ";
            inputToVector(key);

            // Ensure key is right size
            if (key.size() != 16 && key.size() != 24 && key.size() != 32) {

                std::cout << "Invalid key size!!\n Please enter a valid key\n";
                return 2;
            }

            // Decrypt with mode entered by user

            // Decryption with ECB
            if (std::strcmp(mode, "ecb") == 0 || std::strcmp(mode, "ECB") == 0) {
                decrypt_ecb(input, output, key);
            }
            // Decryption with CBC
            else if (std::strcmp(mode, "cbc") == 0 || std::strcmp(mode, "CBC") == 0) {
                // Receive IV
                std::cout << "Enter IV: ";

                inputToVector(iv);

                // Ensure IV size is correct
                if (iv.size() != NUM_BYTES) {
                    std::cout << "Invalid number of bytes entered for IV\n";
                    return 2;
                }

                 algorithmSuccess = decrypt_cbc(input, output, key, iv);

                // Stop execution if encryption is unsuccessful
                if (!algorithmSuccess)
                    return 3;

            }
            // Decryption with CFB
            else if (std::strcmp(mode, "cfb") == 0|| std::strcmp(mode, "CFB") == 0) {
                // Receive IV
                std::cout << "Enter IV: ";
                inputToVector(iv);


                // Ensure IV size is correct
                if (iv.size() != NUM_BYTES) {
                    std::cout << "Invalid number of bytes entered for IV\n";
                    return 2;
                }

                algorithmSuccess = decrypt_cfb(input, output, key, iv);

                // Stop execution if encryption is unsuccessful
                if (!algorithmSuccess)
                    return 3;
            }
            // Decryption with OFB
            else if (std::strcmp(mode, "ofb") == 0 || std::strcmp(mode, "OFB") == 0) {
                // Receive IV
                std::cout << "Enter IV: ";
                inputToVector(iv);


                // Ensure IV size is correct
                if (iv.size() != NUM_BYTES) {
                    std::cout << "Invalid number of bytes entered for IV\n";
                    return 2;
                }

                algorithmSuccess = decrypt_ofb(input, output, key, iv);

                // Stop execution if encryption is unsuccessful
                if (!algorithmSuccess)
                    return 3;
            }
            // Decryption with CTR
            else if (std::strcmp(mode, "ctr") == 0 || std::strcmp(mode, "CTR") == 0) {
                std::array<unsigned char, NUM_BYTES / 2> nonce;
                std::vector<unsigned char> vectorNonce;

                // Receive nonce of initial counter
                std::cout << "Enter nonce: ";
                inputToVector(vectorNonce);

                // Ensure proper number of bytes entered for upper half of initial counter
                if (vectorNonce.size() != NUM_BYTES / 2) {
                    std::cout << "Invalid number of bytes entered for nonce.\n";
                    return 2;
                }


                std::copy(vectorNonce.begin(), vectorNonce.end(), nonce.begin());

                algorithmSuccess = decrypt_ctr(input, output, key, nonce);

                // Stop execution if encryption is unsuccessful
                if (!algorithmSuccess)
                    return 3;
            }

            printDecrpytionResults(output);
        }
    }

    return 0;
}
