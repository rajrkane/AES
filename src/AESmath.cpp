/**
  @file AESmath.cpp: Math and common functions to encryption and decryption
*/
#include "AESmath.hpp"

// From Appendix A of the AES spec
// This is the first byte of the rcon word array which is x^(i-1) in GF(2^8)
std::array<unsigned char, 11> rcon1_i_bytes = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };


/**
  Multiplies a by b in GF(2^8) 
  @param a: the first polynomial
  @param b: the second polynomial
  @return a * b in GF(2^8)
*/
unsigned char galoisFieldMult(unsigned char a, unsigned char b) {
	unsigned char product = 0;
	for (unsigned char i = 0; i < 8; i++) {
		if ((b & 1) == 1) {
			product ^= a;
		}

		unsigned char aHighBit = a & 0x80;
		a = a << 1;
		if (aHighBit) {
			a ^= 0x1b;
		}

		b = b >> 1;
	}

	return product;
}


/**
  Computes the mutiplicative inverse of the polynomial a in GF(2^8)
  @param a: the polynomial to find the inverse of
  @return the inverse of a
*/
unsigned char galoisFieldInv(unsigned char a) {
	unsigned char product = a;

	// The inverse in GF(2^8) is really x^(255-1)
	// This is 253 iterations because the product is already a or a^1
	for (int i = 0; i < 253; i++) {
		product = galoisFieldMult(product, a);
	}

	return product;
}


/**
  Computes the AES key expansion
  @param key: the input key array
  @param expansion: the array to put the key expansion into
                    The array needs 16 * (Nr + 1) bytes or 16 * (keysize/4 + 7) bytes allocated
  @param keysize: the size of the input key in bytes
  				  Note: the key should be 16, 24, or 32 bytes large
  @return none
*/
void keyExpansion(const std::vector<unsigned char>& key, std::vector<unsigned char>&  expansion, unsigned char keysize) {
	int Nk = keysize / 4;
	int Nr = (Nk + 6);

	for (std::size_t i = 0 ; i < keysize; i++) { // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
		expansion[i] = key[i];
	}

	unsigned char temp[4];

	// i < Nb * (Nr + 1)
	//The number of bytes in a word is 4
	for(std::size_t i = Nk; i < (4 * (Nr + 1)); i++) { // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
		temp[0] = expansion[(4 * (i - 1))];
		temp[1] = expansion[(4 * (i - 1)) + 1];
		temp[2] = expansion[(4 * (i - 1)) + 2];
		temp[3] = expansion[(4 * (i - 1)) + 3];

		if (i % Nk == 0) {
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
		else if (Nk > 6 && i % Nk == 4) {
			//SUBWORD
			temp[0] = getSboxValue(temp[0]);
			temp[1] = getSboxValue(temp[1]);
			temp[2] = getSboxValue(temp[2]);
			temp[3] = getSboxValue(temp[3]);
		}

		//w[i] = w[i-Nk] xor temp
		expansion[4 * i] = expansion[4 * (i - Nk)] ^ temp[0];
		expansion[4 * i + 1] = expansion[4 * (i - Nk) + 1] ^ temp[1];
		expansion[4 * i + 2] = expansion[4 * (i - Nk) + 2] ^ temp[2];
		expansion[4 * i + 3] = expansion[4 * (i - Nk) + 3] ^ temp[3];
	}
}


/**
  XORs each byte of the state array with the key.
  @param state: the state array to modify
  @param key: vector of hex values representing the key
  @return none
*/
void addRoundKey(std::array<unsigned char, 16>& state, unsigned char* key) {
	for (std::size_t i = 0; i < NUM_BYTES; i++) { // Secure coding: CTR50-CPP. Guarantee that container indices and iterators are within the valid range
		state[i] = state[i] ^ key[i];
	}
}


/**
  Computes inverse sbox value.
  @param index: byte of state array whose value to compute
  @return inverse sbox value of index
*/
unsigned char getSboxValue(unsigned char index) {
	unsigned char inv = galoisFieldInv(index);
	unsigned char matRow = 0xF1; // 11110001
	unsigned char out = 0;
	
	//Per bit
	for (int i = 0; i < 8; i++) {
		//Find the bits that, when 'multiplied' by the matrix row, are one
		unsigned char app = (unsigned char) ((int)inv & (int)matRow);

		//Every bit of the application
		for (int j = 0; j < 8; j++) {
			//Add the bits together (j) and put it into the corresponding output bit (i)
			out ^= (((app >> j) & 1) << i);
		}

		//Left rotate the matrix row
		matRow = (matRow << 1) | (matRow >> 7);
	}

	return out ^ 0x63;
}


/**
  Computes inverse sbox value.
  @param index: byte of state array whose value to compute
  @return inverse sbox value of index
*/
unsigned char invGetSboxValue(unsigned char index) {
  unsigned char matRow = 0xA4; // 10100100
  unsigned char out = 0;

  // Per bit
  for (int i = 0; i < 8; i++) {
    // Find the bits that, when 'multiplied' by the matrix row, are one
    unsigned char app = (unsigned char) ((int)index & (int)matRow);

    // Every bit of the application
    for (int j = 0; j < 8; j++) {
      // Set output bit to sum of bits
      out ^= (((app >> j) & 1) << i);
    }

    // Left rotate the matrix row
    matRow = (matRow << 1) | (matRow >> 7);
  }

  out ^= 0x5;

  return galoisFieldInv(out);
}
