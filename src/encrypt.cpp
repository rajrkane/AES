// encrypt.cpp
#include "encrypt.hpp"
#include <iostream>

/**
	Substitutes bytes in the state for bytes from a substitution box
	@param state: the state array to modify
	@return none
*/
void subBytes(unsigned char* state) {
	for (int i = 0; i < NUM_BYTES; i++) {
		state[i] = getSboxValue(state[i]);
	}
}

/**
	Left shifts the bytes in each row of the state based on that rows index, i.e. row 0 gets no shift, row 1 once to left...
	@param state: the state array to modify
	@return none
*/
void shiftRows(unsigned char* state) {
	unsigned char shiftedState[NUM_BYTES];

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
	for (int i = 0; i < NUM_BYTES; i++) {
		state[i] = shiftedState[i];
	}
}

/**
	mixColumns, multiplies the columns of the state by the polynomial {02}, {03} shifted around the rows
	@param state: the state array to modify
	@return none
*/
void mixColumns(unsigned char* state) {
	unsigned char tmp[NUM_BYTES];

	for (int i = 0; i < 4; i++) {
		tmp[4 * i] = galoisFieldMult(0x02, state[i * 4]) ^ galoisFieldMult(0x03, state[i * 4 + 1]) ^ state[i * 4 + 2] ^ state[i * 4 + 3];
		tmp[4 * i + 1] = state[i * 4] ^ galoisFieldMult(0x02, state[i * 4 + 1]) ^ galoisFieldMult(0x03, state[i * 4 + 2]) ^ state[i * 4 + 3];
		tmp[4 * i + 2] = state[i * 4] ^ state[i * 4 + 1] ^ galoisFieldMult(0x02, state[i * 4 + 2]) ^ galoisFieldMult(0x03, state[i * 4 + 3]);
		tmp[4 * i + 3] = galoisFieldMult(0x03, state[i * 4]) ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ galoisFieldMult(0x02, state[i * 4 + 3]);
	}

	//Replace the state array with the mixed bytes
	for (int i = 0; i < NUM_BYTES; i++) {
		state[i] = tmp[i];
	}
}

// Since decrypt already has a printstate, leave this commented out so it can compile
void printstate(unsigned char* state)
{
	for (int i = 0; i < NUM_BYTES; i++)
	{
		std::cout << std::hex << (int) state[i];
		std::cout << " ";
	}

	std::cout << std::endl;
}

/**
  Cipher, which implements shiftRows, sSubBytesand mixColumns
  @param input: array of hex values representing the input bytes
  @param output: array of hex values that is copied to from final state
  @param key: key to use
  @param keysize: size of the key
  @return none
*/
void encrypt(std::array<unsigned char, 16> &input, std::array<unsigned char, 16>& output, unsigned char* key, unsigned int keysize) {
	// Create the state array
	unsigned char state[NUM_BYTES];
	// Copy 16 bytes from input into state
	for (int i = 0; i < NUM_BYTES; i++) {
		state[i] = input[i];
	}
	unsigned char* expandedKey = new unsigned char[16 * ((keysize / 4) + 7)];

	keyExpansion(key, expandedKey, keysize);

	// Intial Round
	addRoundKey(state, &(expandedKey[0]));
	//printstate(state);
	
	int numRounds = keysize/4 + 6;

	for (int i = 0; i < numRounds-1; i++) {
		subBytes(state);
		//printstate(state);
		shiftRows(state);
		//printstate(state);
		mixColumns(state);
		//printstate(state);
		//The key index is supposed to be 4 * roundNum but since the key is bytes, its 4*4*roundNum
		addRoundKey(state, &(expandedKey[16*(i+1)]));
		//printstate(state);
	}

	// Final Round - No MixedColumns
	subBytes(state);
	//printstate(state);
	shiftRows(state);
	//printstate(state);
	addRoundKey(state, &(expandedKey[16*numRounds]));
	// printstate(state);

	for (int i = 0; i < NUM_BYTES; i++) {
		output[i] = state[i];
	}
}