// decrypt.cpp
#include "decrypt.hpp"

const int NUM_BYTES = 16;

const unsigned char s_box_inv[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

//Key, which is keysize bytes and expansion which has been allocated 16 * (Nr + 1) bytes or 16 * (keysize/4 + 7) bytes
//The key should be 16, 24, or 32 bytes large
// TODO: consolidate this function and the one in encrypt (they are the same)
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
		//std::cout << i << " ";

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
			temp[0] = getSboxValue(temp[0]);
			temp[1] = getSboxValue(temp[1]);
			temp[2] = getSboxValue(temp[2]);
			temp[3] = getSboxValue(temp[3]);

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

void addRoundKey(unsigned char* state, unsigned char* key) {
  for (int i = 0; i < NUM_BYTES; i++) {
    state[i] = state[i] ^ key[i]
  }
}

void subBytesInv(unsigned char* state);

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

void mixColumnsInv(unsigned char* state);

void decrypt(unsigned char* input, unsigned char* output, unsigned char* key, int keysize) {
  // Create the state array
  unsigned char state[NUM_BYTES];

  // Copy 16 bytes from input into state
  for (int i = 0; i < NUM_BYTES; i++) {
    state[i] = input[i];
  }

  unsigned char* expandedKey = new unsigned char[16 * ((keysize / 4) + 7)];

  keyExpansion(key, expandedKey, keysize);

  int numRounds = keysize/4 + 6;

  // Initial round
  addRoundKey(state, &(expandedKey[numRounds*NUM_BYTES]));

  for (int round = numRounds; round > 1; round--){
    shiftRowsInv(state);
    subBytesInv(state);
    addRoundKey(state, &(expandedKey[round*NUM_BYTES]));
    mixColumnsInv(state);
  }

  // Final round
  shiftRowsInv(state);
  subBytesInv(state);
  addRoundKey(state, &(expandedKey[0]))

  // Set output to state
  for (int i = 0; i < NUM_BYTES; i++) {
    output[i] = state[i];
  }

}