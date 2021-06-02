/**
  @file interface.cpp: Methods for interacting with the user
*/

#include "interface.hpp"



/**
   Print the contents of a vector as bytes
    @param vec: vector of unsigned char values to be printed in hex format
    @return none
 */
void printVector(std::vector<unsigned char>& vec) {
    for(std::size_t i = 0; i < vec.size(); i++) { 
        if((int) vec[i] < 16) {
            std::cout << '0';
        }
        std::cout << std::hex << (int) vec[i] << " ";
    }
    std::cout << std::endl;
}

/**
    Print the ciphertext, and key after an encryption
    Used for modes that do not require an IV (ECB)
    @param ouput: ciphertext received as output from encryption
    @param key: key used for encryption
    @return none
 */
void printEncryptionResults(std::vector<unsigned char>& output, std::vector<unsigned char>& key) {
    std::cout << "\nCIPHERTEXT: ";
    printVector(output);
    std::cout << "KEY: ";
    printVector(key);
}

/**
    Print the ciphertext, key, and IV after an encryption
    Used for modes that require an IV (CBC, CFB, OFB)
    @param ouput: ciphertext received as output from encryption
    @param key: key used for encryption
    @param iv: IV used for encryption in the chosen mode
    @return none
 */
void printEncryptionResults(std::vector<unsigned char>& output, std::vector<unsigned char>& key, std::vector<unsigned char>& iv) {
    std::cout << "\nCIPHERTEXT: ";
    printVector(output);
    std::cout << "KEY: ";
    printVector(key);
    std::cout << "IV: ";
    printVector(iv);
}


/**
    Print the ciphertext, key, and nonce for initial counter after an encryption
    Used for CTR
    @param ouput: ciphertext received as output from encryption
    @param key: key used for encryption
    @param nonce: IV used for encryption in the chosen mode
    @return none
 */
void printEncryptionResults(std::vector<unsigned char>& output, std::vector<unsigned char>& key, std::array<unsigned char, NUM_BYTES / 2>& nonce) {
    std::cout << "\nCIPHERTEXT: ";
    printVector(output);
    std::cout << "KEY: ";
    printVector(key);

    std::vector<unsigned char> vectorNonce;

    // Copy elements of array into vector for printing
    for(std::size_t i = 0; i < nonce.size(); i++) { 
        vectorNonce.push_back(nonce[i]);
    }

    std::cout << "NONCE: ";
    printVector(vectorNonce);
}
/**
    Print the recovered plaintext after a decrpytion
    @param ouput: plaintext recovered as output from encryption
    @return none
 */
void printDecrpytionResults(std::vector<unsigned char>&output) {
    std::cout << "\nDECRPYTED PLAINTEXT: ";
    printVector(output);
}

/**

    @param vec: vector of hex values to be printed
    @return none
 */
int getKeySizeInBytes(char* keySize) {
    int returnSize;

    if(std::strcmp(keySize, "128") == 0)
        returnSize = 16;
    else if(std::strcmp(keySize, "192") == 0)
        returnSize = 24;
    else if(std::strcmp(keySize, "256") == 0)
        returnSize = 32;
    else {
        returnSize = -1;
    }

    return returnSize;
}

/**
    Method for testing. Print the contents of vector as bytes
    @param vec: vector of hex values to be printed
    @return none
 */
void inputToVector(std::vector<unsigned char>& vec) {
    std::string line;
    unsigned char char_iterator;;

    std::getline(std::cin, line);

    // Remove spaces from input
    std::string::iterator end_pos = std::remove(line.begin(), line.end(), ' ');
    line.erase(end_pos, line.end());


    // Convert each byte to integer, then store as unsigned char in input vector
    for (std::size_t i = 0; i < line.size(); i += 2) { 
        unsigned char byteValue = (unsigned char) std::stoi(line.substr(i, 2), nullptr, 16);
        vec.push_back(byteValue); 
    }
}
