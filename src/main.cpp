/// main.cpp

#include <iostream>
#include <string>
#include <algorithm>
#include <cstring>
#include "AESRand.hpp"
#include "AESmodes.hpp"
#include "encrypt.hpp"
#include "decrypt.hpp"

/**
    Method for testing. Print the contents of vector as bytes
    @param vec: vector of hex values to be printed
    @return none
 */

void printVector(std::vector<unsigned char> vec);
void printEncryptionResults(std::vector<unsigned char> input, std::vector<unsigned char> output, std::vector<unsigned char> key);
void printDecrpytionResults(std::vector<unsigned char> output);

// Command line arguments: ./main [enc, encrypt/ dec, decrypt] [ecb/cbc/cfb/ofb/ctr] [key/ ]
int main(int argc, char** argv) {
    AESRand rand;
    std::vector<unsigned char> input;
    std::vector<unsigned char> output;
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;

    const int IV_SIZE = 16;
    std::string line;
    unsigned char char_iterator;


    if(argc > 3) {
        char* aes_function = argv[1];
        char* mode = argv[2];
        char* key_type = argv[3];

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

            // Create key
            key = rand.generateBytes(16);

            // Encrypt with mode entered by user

            if (std::strcmp(mode, "ecb") == 0 || std::strcmp(mode, "ECB") == 0) {
                encrypt_ecb(input, output, key);
            }
            else if (std::strcmp(mode, "cbc") || std::strcmp(mode, "CBC")) {
                iv = rand.generateBytes(IV_SIZE);
                encrypt_cbc(input, output, key, iv);
            }
            else if (std::strcmp(mode, "cfb") || std::strcmp(mode, "CFB")) {
                std::cout << "CFB encryption\n";
            }
            else if (std::strcmp(mode, "ofb") || std::strcmp(mode, "OFB")) {
                std::cout << "OFB encryption\n";
            }
            else if (std::strcmp(mode, "ctr") || std::strcmp(mode, "CTR")) {
                std::cout << "CTR encryption\n";
            }

            printEncryptionResults(input, output, key);

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

            // Convert each byte to integer, then store as unsigned char in input vector
            for (std::size_t i = 0; i < line.size(); i += 2) {
                unsigned char byteValue = (unsigned char) std::stoi(line.substr(i, 2), nullptr, 16);
                input.push_back(byteValue);
            }

            // Receive key
            std::cout << "Enter key: ";

            std::getline(std::cin, line);

            // Remove spaces from input
            end_pos = std::remove(line.begin(), line.end(), ' ');
            line.erase(end_pos, line.end());


            // Convert each byte to integer, then store as unsigned char in input vector
            for (std::size_t i = 0; i < line.size(); i += 2) {
                unsigned char byteValue = (unsigned char) std::stoi(line.substr(i, 2), nullptr, 16);
                key.push_back(byteValue);
            }

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
            else if (std::strcmp(mode, "cbc") || std::strcmp(mode, "CBC")) {
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
            else if (std::strcmp(mode, "cfb") || std::strcmp(mode, "CFB")) {
                std::cout << "CFB decryption\n";
            }
            else if (std::strcmp(mode, "ofb") || std::strcmp(mode, "OFB")) {
                std::cout << "OFB decryption\n";
            }
            else if (std::strcmp(mode, "ctr") || std::strcmp(mode, "CTR")) {
                std::cout << "CTR decryption\n";
            }

            printDecrpytionResults(output);
        }

    }
//   printVector(input);

    //std::cout << std::hex << std::stoi(line, nullptr, 16);

    // Add bytes to the input vector



//    std::cout.setf(std::ios_base::hex, std::ios_base::basefield);
//    for(int i = 0; i < IV.size(); i++) {
//        std::cout << (int) IV[i] << " ";
//    }

//    for(int i = 0; i < input.size(); i++) {
//        std::cout << input[i] << " ";
//    }
//    std::cout << std::endl;


//    std::vector<unsigned char> key1 = rand.generateBytes(16);
//    std::cout << "Key 1:";
//    for(int i = 0; i < key1.size(); i++) {
//        std::cout << std::hex << (int) key1[i] << " ";
//    }
//    std::cout << std::endl;

    return 0;
}


void printVector(std::vector<unsigned char> vec) {
    for(unsigned char c : vec) {
        if((int) c < 16) {
            std::cout << '0';
        }
        std::cout << std::hex << (int) c << " ";
    }
    std::cout << std::endl;
}


void printEncryptionResults(std::vector<unsigned char> input, std::vector<unsigned char> output, std::vector<unsigned char> key) {
    std::cout << "PLAINTEXT: ";
    printVector(input);
    std::cout << "KEY: ";
    printVector(key);
    std::cout << "CIPHERTEXT: ";
    printVector(output);
}

void printDecrpytionResults(std::vector<unsigned char> output) {
    std::cout << "DECRPYTED PLAINTEXT: ";
    printVector(output);
}