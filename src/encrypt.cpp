// encrypt.cpp
#include "encrypt.hpp"

// Number of bytes in the state - 128 bits
const int NUM_BYTES = 16;

// Rijndael Substituion table
// Copied from https://cryptography.fandom.com/wiki/Rijndael_S-box
int s_box[256] =
{ 0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76
,0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0
,0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15
,0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75
,0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84
,0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf
,0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8
,0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2
,0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73
,0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb
,0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79
,0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08
,0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a
,0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e
,0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf
,0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16 };

//From Appendix A of the AES spec
//This is the first byte of the rcon word array which is x^(i-1) in GF(2^8)
unsigned char rcon1_i_bytes[11] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

//Key, which is keysize bytes and expansion which has been allocated 16 * (Nr + 1) bytes or 16 * (keysize/4 + 7) bytes
//The key should be 16, 24, or 32 bytes large
void keyExpansion(unsigned char* key, unsigned char* expansion, unsigned char keysize) {

	int i = 0;
	int Nk = keysize / 4;
	int Nr = (Nk + 6);

	for ( ; i < keysize; i++)
	{
		expansion[i] = key[i];
	}

	i = Nk;
	unsigned char temp[4];

	// i < Nb * (Nr + 1)
	//The number of bytes in a word is 4
	while (i < (4 * (Nr + 1)))
	{
		std::cout << i << " ";

		temp[0] = expansion[(4 * (i - 1))];
		temp[1] = expansion[(4 * (i - 1)) + 1];
		temp[2] = expansion[(4 * (i - 1)) + 2];
		temp[3] = expansion[(4 * (i - 1)) + 3];

		if (i % Nk == 0)
		{
			//ROTWORD on temp
			unsigned char rotTemp = temp[0];
			temp[0] = temp[1];
			temp[1] = temp[2];
			temp[2] = temp[3];
			temp[3] = rotTemp;

			//SUBWORD
			temp[0] = s_box[temp[0]];
			temp[1] = s_box[temp[1]];
			temp[2] = s_box[temp[2]];
			temp[3] = s_box[temp[3]];

			//Xor with Rcon[i/Nk]
			//Since the last 3 bytes of Rcon are always zero, then temp[0] is the only byte changing
			temp[0] ^= rcon1_i_bytes[(i / Nk) - 1];
		}
		else if (Nk > 6 && i % Nk == 4)
		{
			//SUBWORD
			temp[0] = s_box[temp[0]];
			temp[1] = s_box[temp[1]];
			temp[2] = s_box[temp[2]];
			temp[3] = s_box[temp[3]];
		}

		//w[i] = w[i-Nk] xor temp
		expansion[4 * i] = expansion[4 * (i - Nk)] ^ temp[0];
		expansion[4 * i + 1] = expansion[4 * (i - Nk) + 1] ^ temp[1];
		expansion[4 * i + 2] = expansion[4 * (i - Nk) + 2] ^ temp[2];
		expansion[4 * i + 3] = expansion[4 * (i - Nk) + 3] ^ temp[3];
		i++;
	}
}

void subBytes(unsigned char* state) {
	for (int i = 0; i < NUM_BYTES; i++) {
		state[i] == s_box[state[i]];
	}
}
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

	for (int i = 0; i < NUM_BYTES; i++) {
		state[i] = shiftedStates[i];
	}
}


void mixColumns(unsigned char* state) {
	// Not implemented 
}

// XOR each byte of state and key
void addRoundKey(unsigned char* state, unsigned char* key) {
	for (int i = 0; i < NUM_BYTES; i++) {
		state[i] = state[i] ^ key[i];
	}
}

void encrpyt(unsigned char* input, unsigned char* output, unsigned char* key) {
	// Create the state array
	unsigned char state[NUM_BYTES] = input;

	// Copy 16 bytes from input into state
	for (int i = 0; i < NUM_BYTES; i++) {
		state[i] = input[i];
	}
	
	//Hardcode key size for now
	unsigned int keysize = 16;

	unsigned char expandedKey[16 * (keysize/4 + 7)]

	keyExpansion(key, expandedKey, keysize);

	// Intial Round
	addRoundKey(state, &(expandedKey[0]));

	// Round = 
	int numRounds = keysize/4 + 6;

	for (int i = 0; i < numRounds; i++) {
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		//The key index is supposed to be 4 * roundNum but since the key is bytes, its 4*4*roundNum
		addRoundKey(state, &(expandedKey[16*i]));
	}

	// Final Round - No MixedColumns
	subBytes(state);
	shiftRows(state);
	addRoundKey(state, &(expandedKey[16*numRounds]));
}