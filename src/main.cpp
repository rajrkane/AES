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


//void printVector(std::vector<unsigned char>& vec);
//void printEncryptionResults(std::vector<unsigned char>& input, std::vector<unsigned char>& output, std::vector<unsigned char>& key);
//void printEncryptionResults(std::vector<unsigned char>& input, std::vector<unsigned char>& output, std::vector<unsigned char>& key, std::vector<unsigned char>& iv);
//void printDecrpytionResults(std::vector<unsigned char>& output);
//int getKeySizeInBytes(char* keySize);
//void inputToVector(std::vector<unsigned char>& vec);


// USAGE: ./main [enc, encrypt/ dec, decrypt] [ecb/cbc/cfb/ofb/ctr] [-r/-k/-kf] [128, 192, 256] (-f) (-iv/-nonce)
// [] - required parameters
// () - optional parameters

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

    if(argc > 4) {
        char* aes_function = argv[1];
        char* mode = argv[2];
        char* keyType = argv[3];
        char* keySize = argv[4];

        int keyByteSize = getKeySizeInBytes(keySize);

        // If invalid key size is entered, output error message and terminate program
        if (keyByteSize == -1) {
            std::cout << "Invalid parameter for key size.\n";
            return 2;
        }

        // Encrypt

        if (std::strcmp(aes_function, "encrypt") == 0 || std::strcmp(aes_function, "enc") == 0) {

            // Receive plaintext to encrypt
            std::cout << "Enter plaintext: ";

            std::getline(std::cin, line);

            // Remove spaces from input
            std::string::iterator end_pos = std::remove(line.begin(), line.end(), ' ');
            line.erase(end_pos, line.end());

            // Ensure input has length divisible by 2
            if (line.size() % 2 != 0) {
                std::cout << "Invalid input!!\n Please ensure that each byte is entered with 2 hex values\n";
                return 1;
            }


            // Convert each byte to integer, then store as unsigned char in input vector
            for (std::size_t i = 0; i < line.size(); i += 2) {
                unsigned char byteValue = (unsigned char) std::stoi(line.substr(i, 2), nullptr, 16);
                input.push_back(byteValue);
            }

            // Create random key
            if(std::strcmp(keyType, "-r") == 0) {
                key = rand.generateBytes(keyByteSize);
            }
            // Receive key from user input
            else if(std::strcmp(keyType, "-k") == 0) {
                std::cout << "Enter key: ";
                inputToVector(key);
                // Check that user entered correct number of bytes for designated key size
                if(key.size() != keyByteSize) {
                    std::cout << "Invalid number of bytes entered for key.\n";
                    return 2;
                }

            }
            // Receive file path for key
            // TODO Implement reading key from file
            else if(std::strcmp(keyType, "-kf") == 0) {
                std::cout << "Enter file path for key: ";
            }

            // Encrypt with mode entered by user

            // Encryption with ECB
            if (std::strcmp(mode, "ecb") == 0 || std::strcmp(mode, "ECB") == 0) {
                algorithmSuccess = encrypt_ecb(input, output, key);

                // Stop execution if encryption is unsuccessful
                if (!algorithmSuccess)
                    return 3;

                printEncryptionResults(input, output, key);
            }
            // Encryption with CBC
            else if (std::strcmp(mode, "cbc") == 0 || std::strcmp(mode, "CBC") == 0) {
                // If -iv command line argument is provided, receive value of IV from user
                if ((argc == 6 && std::strcmp(argv[5], "-iv") == 0) || (argc == 7 && std::strcmp(argv[6], "-iv") == 0)) {
                    std::cout << "Enter IV: ";
                    inputToVector(iv);
                }
                else {
                    iv = rand.generateBytes(IV_SIZE);
                }
                algorithmSuccess = encrypt_cbc(input, output, key, iv);

                // Stop execution if encryption is unsuccessful
                if (!algorithmSuccess)
                    return 3;

                printEncryptionResults(input, output, key, iv);
            }
            // Encryption with CFB
            else if (std::strcmp(mode, "cfb") == 0 || std::strcmp(mode, "CFB") == 0) {
                // If -iv command line argument is provided, receive value of IV from user
                if ((argc == 6 && std::strcmp(argv[5], "-iv") == 0) || (argc == 7 && std::strcmp(argv[6], "-iv") == 0)) {
                    std::cout << "Enter IV: ";
                    inputToVector(iv);
                }
                else {
                    iv = rand.generateBytes(IV_SIZE);
                }

                algorithmSuccess = encrypt_cfb(input, output, key, iv);

                // Stop execution if encryption is unsuccessful
                if (!algorithmSuccess)
                    return 3;

                printEncryptionResults(input, output, key, iv);
            }
            // Encryption with OFB
            else if (std::strcmp(mode, "ofb") == 0 || std::strcmp(mode, "OFB") == 0) {
                // If -iv command line argument is provided, receive value of IV from user
                if ((argc == 6 && std::strcmp(argv[5], "-iv") == 0) || (argc == 7 && std::strcmp(argv[6], "-iv") == 0)) {
                    std::cout << "Enter IV: ";
                    inputToVector(iv);
                }
                else {
                    iv = rand.generateBytes(IV_SIZE);
                }
                algorithmSuccess = encrypt_ofb(input, output, key, iv);

                // Stop execution if encryption is unsuccessful
                if (!algorithmSuccess)
                    return 3;

                printEncryptionResults(input, output, key, iv);
            }
            // Encryption with CTR
            else if (std::strcmp(mode, "ctr") == 0 || std::strcmp(mode, "CTR") == 0) {
                std::array<unsigned char, NUM_BYTES / 2> nonce;
                std::vector<unsigned char> vectorNonce;

                // Set value of nonce
                // If -nonce command line argument is provided, receive value of nonce from user
                if ((argc == 6 && std::strcmp(argv[5], "-nonce") == 0) || (argc == 7 && std::strcmp(argv[6], "-nonce") == 0)) {
                    std::cout << "Enter nonce: ";
                    inputToVector(vectorNonce);

                    if(nonce.size() != NUM_BYTES / 2) {
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

//                // TODO Print out valid format for nonce in CTR mode
//                printEncryptionResults(input, output, key, nonce);
            }

            //printEncryptionResults(input, output, key);

        }

        // Decrypt functionality

        if(std::strcmp(argv[1], "decrypt") == 0 || std::strcmp(argv[1], "dec") == 0) {
            // Receive ciphertext to decrypt
            std::cout << "Enter ciphertext: ";

            std::getline(std::cin, line);

            // Remove spaces from input
            std::string::iterator end_pos = std::remove(line.begin(), line.end(), ' ');
            line.erase(end_pos, line.end());

            // Ensure input has length divisible by 2
            if (line.size() % 2 != 0) {
                std::cout << "Invalid input!!\n Please ensure that each byte is entered with 2 hex values\n";
                return 1;
            }


            // Convert each byte to integer, then store as unsigned char in input vector
            for (std::size_t i = 0; i < line.size(); i += 2) {
                unsigned char byteValue = (unsigned char) std::stoi(line.substr(i, 2), nullptr, 16);
                input.push_back(byteValue);
            }

            // Receive key
            std::cout << "Enter key: ";

            inputToVector(key);

            // Ensure key is right size
            std::cout << key.size() << std::endl;
            if (key.size() != 16 && key.size() && 24 && key.size() != 32) {
                std::cout << "Invalid key size!!\n Please enter a valid key\n";
                return 2;
            }

            // Decrypt with mode entered by user
            if (std::strcmp(mode, "ecb") == 0 || std::strcmp(mode, "ECB") == 0) {
                decrypt_ecb(input, output, key);
            }
            else if (std::strcmp(mode, "cbc") == 0 || std::strcmp(mode, "CBC") == 0) {
                // Receive IV
                std::cout << "Enter IV: ";

                std::getline(std::cin, line);

                // Remove spaces from input
                std::string::iterator end_pos = std::remove(line.begin(), line.end(), ' ');
                line.erase(end_pos, line.end());

                // Ensure input has length divisible by 2
                if (line.size() != 32) {
                    std::cout << "Invalid key size!!\n Please enter a valid key\n";
                    return 2;
                }


                // Convert each byte to integer, then store as unsigned char in input vector
                for (std::size_t i = 0; i < line.size(); i += 2) {
                    unsigned char byteValue = (unsigned char) std::stoi(line.substr(i, 2), nullptr, 16);
                    iv.push_back(byteValue);
                }

                decrypt_cbc(input, output, key, iv);
            }
            else if (std::strcmp(mode, "cfb") == 0|| std::strcmp(mode, "CFB") == 0) {
                std::cout << "CFB decryption\n";
            }
            else if (std::strcmp(mode, "ofb") == 0 || std::strcmp(mode, "OFB") == 0) {
                std::cout << "OFB decryption\n";
            }
            else if (std::strcmp(mode, "ctr") == 0 || std::strcmp(mode, "CTR") == 0) {
                std::cout << "CTR decryption\n";
            }

            printDecrpytionResults(output);
        }

    }

    return 0;
}
