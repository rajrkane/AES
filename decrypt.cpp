/**
  @file decrypt.cpp: Inverse cipher implementation
*/
#include "decrypt.hpp"
#include <iostream>

/**
  Inverse of shiftRows(). Shifts bytes in last three rows of state over different offsets.
  @param state: state array to modify
  @return none
*/
void invShiftRows(std::array<unsigned char, NUM_BYTES>& state) {
  std::array<unsigned char, NUM_BYTES> shiftedState;

  // Row 1 - Bytes remain unchanged
  shiftedState[0] = state[0];
  shiftedState[4] = state[4];
  shiftedState[8] = state[8];
  shiftedState[12] = state[12];

  // Row 2 - Bytes are shifted over three positions to the left
  shiftedState[1] = state[13];
  shiftedState[5] = state[1];
  shiftedState[9] = state[5];
  shiftedState[13] = state[9];

  // Row 3 - Bytes are shifted over two positions to the left
  shiftedState[2] = state[10];
  shiftedState[6] = state[14];
  shiftedState[10] = state[2];
  shiftedState[14] = state[6];

  // Row 4 - Bytes are shifted over one position to the left
  shiftedState[3] = state[7];
  shiftedState[7] = state[11];
  shiftedState[11] = state[15];
  shiftedState[15] = state[3];

  for (std::size_t i = 0; i < NUM_BYTES; i++) { // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
    state[i] = shiftedState[i]; // Secure coding: OOP57-CPP. Prefer special member functions and overloaded operators to C Standard Library functions
  }
}


/**
  Inverse of subBytes(). Replaces each byte of state with computed inverse sbox value.
  @param state: state array to modify
  @return none
*/
void invSubBytes(std::array<unsigned char, NUM_BYTES>& state) {
  for (std::size_t i = 0; i < NUM_BYTES; i++) { // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
    state[i] = invGetSboxValue(state[i]);
  }
}


/**
  Inverse of mixColumns(). Multiplies columns of state by polynomial {0b},{0d},{09},{0e} mod x^4 +1 over GF(2^8).
  @param state: state array to modify
  @return none
*/
void invMixColumns(std::array<unsigned char, NUM_BYTES>& state) {
  std::array<unsigned char, NUM_BYTES> tmp;

	for (std::size_t i = 0; i < 4; i++) { // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
		tmp[4 * i] = galoisFieldMult(0x0e, state[i * 4]) ^ galoisFieldMult(0x0b, state[i * 4 + 1]) ^ galoisFieldMult(0x0d, state[i * 4 + 2]) ^ galoisFieldMult(0x09, state[i * 4 + 3]);
		tmp[4 * i + 1] = galoisFieldMult(0x09, state[i * 4]) ^ galoisFieldMult(0x0e, state[i * 4 + 1]) ^ galoisFieldMult(0x0b, state[i * 4 + 2]) ^ galoisFieldMult(0x0d, state[i * 4 + 3]);
		tmp[4 * i + 2] = galoisFieldMult(0x0d, state[i * 4]) ^ galoisFieldMult(0x09, state[i * 4 + 1]) ^ galoisFieldMult(0x0e, state[i * 4 + 2]) ^ galoisFieldMult(0x0b, state[i * 4 + 3]);
		tmp[4 * i + 3] = galoisFieldMult(0x0b, state[i * 4]) ^ galoisFieldMult(0x0d, state[i * 4 + 1]) ^ galoisFieldMult(0x09, state[i * 4 + 2]) ^ galoisFieldMult(0x0e, state[i * 4 + 3]);
	}

	for (std::size_t i = 0; i < NUM_BYTES; i++) { // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
		state[i] = tmp[i]; // Secure coding: OOP57-CPP. Prefer special member functions and overloaded operators to C Standard Library functions
	}
}


/**
  Inverse cipher, which implements invShiftRows, invSubBytes, invMixColumns
  @param input: array of hex values representing output of cipher
  @param output: array of hex values that is copied to from final state
  @param key: key to use
  @param keysize: size of the key
  @return none
*/
void decrypt(std::array<unsigned char, 16> input, std::array<unsigned char, 16>& output, const std::vector<unsigned char>& key) {
  // Create the state array from input
  std::array<unsigned char, NUM_BYTES> state;
  for (std::size_t i = 0; i < NUM_BYTES; i++) { // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
    state[i] = input[i]; // Secure coding: OOP57-CPP. Prefer special member functions and overloaded operators to C Standard Library functions
  }

  // Expand key
  const std::size_t keysize = key.size();
  const std::size_t numRounds = keysize/4 + 6;
  std::vector<unsigned char> expandedKey;
  expandedKey.reserve(16 * (numRounds + 1)); 
	keyExpansion(key, expandedKey, keysize);

  // Initial round
  addRoundKey(state, &(expandedKey[numRounds*NUM_BYTES]));

  // Rounds
  for (std::size_t round = numRounds-1; round > 0; round--){ // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, &(expandedKey[round*NUM_BYTES]));
    invMixColumns(state);
  }

  // Final round
  invShiftRows(state);
  invSubBytes(state);
  addRoundKey(state, &(expandedKey[0]));

  // Set output to state
  for (std::size_t i = 0; i < NUM_BYTES; i++) { // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
    output[i] = state[i]; // Secure coding: OOP57-CPP. Prefer special member functions and overloaded operators to C Standard Library functions
  }
}