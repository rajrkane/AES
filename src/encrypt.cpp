// encrypt.cpp
#include "encrypt.hpp"
#include <iostream>


/**
	Substitutes bytes in the state for bytes from a substitution box
	@param state: the state array to modify
	@return none
*/
void subBytes(std::array<unsigned char, 16>& state) {
	for (std::size_t i = 0; i < 16; i++) {
		state[i] = getSboxValue(state[i]);
	}
}

/**
	Left shifts the bytes in each row of the state based on that rows index, i.e. row 0 gets no shift, row 1 once to left...
	@param state: the state array to modify
	@return none
*/
void shiftRows(std::array<unsigned char, 16>& state) {
	std::array<unsigned char, 16> shiftedState;

	// Row 1 - Bytes remain unchanged
	shiftedState[0] = state[0];
	shiftedState[4] = state[4];
	shiftedState[8] = state[8];
	shiftedState[12] = state[12];

	// Row 2 - Bytes are shifted over one position to the left
	shiftedState[1] = state[5];
	shiftedState[5] = state[9];
	shiftedState[9] = state[13];
	shiftedState[13] = state[1];

	// Row 2 - Bytes are shifted over two positions to the left
	shiftedState[2] = state[10];
	shiftedState[6] = state[14];
	shiftedState[10] = state[2];
	shiftedState[14] = state[6];

	// Row 4 - Bytes are shifted over three positions to the left
	shiftedState[3] = state[15];
	shiftedState[7] = state[3];
	shiftedState[11] = state[7];
	shiftedState[15] = state[11];

	//Replace the state array with the shifted bytes
	for (std::size_t i = 0; i < 16; i++) {
		state[i] = shiftedState[i];
	}
}

/**
	mixColumns, multiplies the columns of the state by the polynomial {02}, {03} shifted around the rows
	@param state: the state array to modify
	@return none
*/
void mixColumns(std::array<unsigned char, 16>& state) {
	std::array<unsigned char, 16> tmp;

	for (std::size_t i = 0; i < 4; i++) {
		tmp[4 * i] = galoisFieldMult(0x02, state[i * 4]) ^ galoisFieldMult(0x03, state[i * 4 + 1]) ^ state[i * 4 + 2] ^ state[i * 4 + 3];
		tmp[4 * i + 1] = state[i * 4] ^ galoisFieldMult(0x02, state[i * 4 + 1]) ^ galoisFieldMult(0x03, state[i * 4 + 2]) ^ state[i * 4 + 3];
		tmp[4 * i + 2] = state[i * 4] ^ state[i * 4 + 1] ^ galoisFieldMult(0x02, state[i * 4 + 2]) ^ galoisFieldMult(0x03, state[i * 4 + 3]);
		tmp[4 * i + 3] = galoisFieldMult(0x03, state[i * 4]) ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ galoisFieldMult(0x02, state[i * 4 + 3]);
	}

	//Replace the state array with the mixed bytes
	for (std::size_t i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}


/**
  Cipher, which implements shiftRows, sSubBytesand mixColumns
  @param input: array of hex values representing the input bytes
  @param output: array of hex values that is copied to from final state
  @param key: vector of hex values representing key to use
  @return none
*/
void encrypt(std::array<unsigned char, 16>& input, std::array<unsigned char, 16>& output, const std::vector<unsigned char>& key) {
  // Create the state array from input
  std::array<unsigned char, 16> state;
	for (std::size_t i = 0; i < 16; i++) {
		state[i] = input[i];
	}

  // Expand key
  const std::size_t keysize = key.size();
  const std::size_t numRounds = keysize/4 + 6;
  std::vector<unsigned char> expandedKey;
  expandedKey.reserve(16 * (numRounds + 1));
	keyExpansion(key, expandedKey, keysize);

	// Intial Round
	addRoundKey(state, &(expandedKey[0]));

	for (std::size_t i = 0; i < numRounds-1; i++) {
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		//The key index is supposed to be 4*roundNum but since the key is bytes, it is 4*4*roundNum
		addRoundKey(state, &(expandedKey[16*(i+1)]));
	}

	// Final Round - No MixedColumns
	subBytes(state);
	shiftRows(state);
	addRoundKey(state, &(expandedKey[16*numRounds]));

	for (std::size_t i = 0; i < 16; i++) {
		output[i] = state[i];
	}
}

// int main() {
//   const std::vector<unsigned char> key = {
//     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
//   };
//   std::array<unsigned char, 16> output;
//   std::array<unsigned char, 16> input = {
//     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
//   };
//   encrypt(input, output, key);
//   for (int i=0; i<16; i++) {
//     std::cout << std::hex << (int) output[i];
//     std::cout << " ";
//   }
// }