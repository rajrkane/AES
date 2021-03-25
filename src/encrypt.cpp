// encrypt.cpp
#include "encrypt.hpp"
#include <iostream>

// Number of bytes in the state - 128 bits
const int NUM_BYTES = 16;

//From Appendix A of the AES spec
//This is the first byte of the rcon word array which is x^(i-1) in GF(2^8)
unsigned char rcon1_i_bytes[11] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

//Multiplies a by b in GF(2^8) 
unsigned char galoisFieldMult(unsigned char a, unsigned char b)
{
	unsigned char product = 0;
	for (unsigned char i = 0; i < 8; i++)
	{
		if ((b & 1) == 1)
		{
			product ^= a;
		}

		unsigned char aHighBit = a & 0x80;
		a = a << 1;
		if (aHighBit)
		{
			a ^= 0x1b;
		}

		b = b >> 1;
	}

	return product;
}

unsigned char galoisFieldInv(unsigned char a)
{
	unsigned char product = a;

	//The inverse in GF(2^8) is really x^(255-1)
	//This is 253 iterations because the product is already a or a^1
	for (int i = 0; i < 253; i++)
	{
		product = galoisFieldMult(product, a);
	}

	return product;
}

unsigned char getSboxValue(unsigned char index)
{
	unsigned char inv = galoisFieldInv(index);
	unsigned char matRow = 0xF1;
	unsigned char out = 0;
	
	//Per bit
	for (int i = 0; i < 8; i++)
	{
		//Find the bits that, when 'multiplied' by the matrix row, are one
		unsigned char app = (unsigned char) ((int)inv & (int)matRow);

		//Every bit of the application
		for (int j = 0; j < 8; j++)
		{
			//Add the bits together (j) and put it into the corresponding output bit (i)
			out ^= (((app >> j) & 1) << i);
		}

		//Left rotate the matrix row
		matRow = (matRow << 1) | (matRow >> 7);
	}

	return out ^ 0x63;
}

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

void subBytes(unsigned char* state) {
	for (int i = 0; i < NUM_BYTES; i++) {
		state[i] = getSboxValue(state[i]);
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
		state[i] = shiftedState[i];
	}
}


void mixColumns(unsigned char* state) {
	unsigned char tmp[NUM_BYTES];

	for (int i = 0; i < 4; i++)
	{
		tmp[4 * i] = galoisFieldMult(0x02, state[i * 4]) ^ galoisFieldMult(0x03, state[i * 4 + 1]) ^ state[i * 4 + 2] ^ state[i * 4 + 3];
		tmp[4 * i + 1] = state[i * 4] ^ galoisFieldMult(0x02, state[i * 4 + 1]) ^ galoisFieldMult(0x03, state[i * 4 + 2]) ^ state[i * 4 + 3];
		tmp[4 * i + 2] = state[i * 4] ^ state[i * 4 + 1] ^ galoisFieldMult(0x02, state[i * 4 + 2]) ^ galoisFieldMult(0x03, state[i * 4 + 3]);
		tmp[4 * i + 3] = galoisFieldMult(0x03, state[i * 4]) ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ galoisFieldMult(0x02, state[i * 4 + 3]);
	}

	for (int i = 0; i < NUM_BYTES; i++) {
		state[i] = tmp[i];
	}
}

// XOR each byte of state and key
void addRoundKey(unsigned char* state, unsigned char* key) {
	for (int i = 0; i < NUM_BYTES; i++) {
		state[i] = state[i] ^ key[i];
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

void encrypt(unsigned char* input, unsigned char* output, unsigned char* key, unsigned int keysize) {
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

	// Round = 
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
	//printstate(state);

	for (int i = 0; i < NUM_BYTES; i++){
		output[i] = state[i];
	}
}