// decrypt.cpp
#include "decrypt.hpp"
#include "AESmath.hpp"
#include <iostream>

void subBytesInv(unsigned char* state) {
  for (int i = 0; i < NUM_BYTES; i++) {
    state[i] = getSboxValueInv(state[i]);
  }
}

void shiftRowsInv(unsigned char* state) {
  unsigned char shiftedState[NUM_BYTES];

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

    for (int i = 0; i < NUM_BYTES; i++) {
      state[i] = shiftedState[i];
    }
}

void mixColumnsInv(unsigned char* state) {
  unsigned char tmp[NUM_BYTES];

	for (int i = 0; i < 4; i++) {
		tmp[4 * i] = galoisFieldMult(0x0e, state[i * 4]) ^ galoisFieldMult(0x0b, state[i * 4 + 1]) ^ galoisFieldMult(0x0d, state[i * 4 + 2]) ^ galoisFieldMult(0x09, state[i * 4 + 3]);
		tmp[4 * i + 1] = galoisFieldMult(0x09, state[i * 4]) ^ galoisFieldMult(0x0e, state[i * 4 + 1]) ^ galoisFieldMult(0x0b, state[i * 4 + 2]) ^ galoisFieldMult(0x0d, state[i * 4 + 3]);
		tmp[4 * i + 2] = galoisFieldMult(0x0d, state[i * 4]) ^ galoisFieldMult(0x09, state[i * 4 + 1]) ^ galoisFieldMult(0x0e, state[i * 4 + 2]) ^ galoisFieldMult(0x0b, state[i * 4 + 3]);
		tmp[4 * i + 3] = galoisFieldMult(0x0b, state[i * 4]) ^ galoisFieldMult(0x0d, state[i * 4 + 1]) ^ galoisFieldMult(0x09, state[i * 4 + 2]) ^ galoisFieldMult(0x0e, state[i * 4 + 3]);
	}

	for (int i = 0; i < NUM_BYTES; i++) {
		state[i] = tmp[i];
	}
}

void printstate(unsigned char* state)
{
	for (int i = 0; i < NUM_BYTES; i++)
	{
		std::cout << std::hex << (int) state[i];
		std::cout << " ";
	}

	std::cout << std::endl;
}

void decrypt(unsigned char* input, unsigned char* output, unsigned char* key, int keysize) {
  // Create the state array
  unsigned char state[NUM_BYTES];

  // Copy 16 bytes from input into state
  for (int i = 0; i < NUM_BYTES; i++) {
    state[i] = input[i];
  }
  printstate(state);

  unsigned char* expandedKey = new unsigned char[16 * ((keysize / 4) + 7)];
  keyExpansion(key, expandedKey, keysize);
  int numRounds = keysize/4 + 6;

  // Initial round
  addRoundKey(state, &(expandedKey[numRounds*NUM_BYTES]));
  printstate(state);

  for (int round = numRounds; round > 1; round--){
    shiftRowsInv(state);
    printstate(state);
    subBytesInv(state);
    printstate(state);
    addRoundKey(state, &(expandedKey[round*NUM_BYTES]));
    printstate(state);
    mixColumnsInv(state);
    printstate(state);
  }

  // Final round
  shiftRowsInv(state);
  printstate(state);
  subBytesInv(state);
  printstate(state);
  addRoundKey(state, &(expandedKey[0]));
  printstate(state);

  // Set output to state
  for (int i = 0; i < NUM_BYTES; i++) {
    output[i] = state[i];
  }
}

int main() {
  unsigned char input[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
  }; 
  unsigned char output[16];
  unsigned char key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };
  int keysize = 16;
  decrypt(input, output, key, keysize);
}