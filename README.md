## Advanced Encryption Standard (AES)
This is an AES cipher implementation with multiple modes of operation. For more information about this implementation, see the report.

### To compile:
Run `make` in the root directory of this repository

### To run:
Command: `./main [enc, encrypt/ dec, decrypt] [ecb/cbc/cfb/ofb/ctr] [-r/-k] [128, 192, 256] (-iv/-nonce)`

`[]` - required parameters*
`()` - optional parameters
`*[-r/-k]` omitted for decryption

First option is to select encryption or decryption

Second option is to select the mode of operation:
		`ecb`: Electronic Code Book
		`cbc`: Cipher Block Chaining
		`cfb`: Cipher Feedback
		`ofb`: Output Feedback
		`ctr`: Counter Mode

Third option is to use a `[-r]`andom key or to provide your own `[-k]`ey
				
- If you select the option to provide you own key, the program will prompt you for the key in hexadecimal
- If you are decrypting, then omit this flag, the program will prompt you for the key

Fourth option is to select the key size for the cipher

Last option is to provide either an `[-iv]` for CBC, CFB and OFB modes or a `[-nonce]` for CTR mode

- If you select either of the options, the program will prompt you for the IV or nonce
- This flag is also omitted during decryption, the program will prompt you for the IV or nonce

### To use:
	
**Encryption**: 

*All Modes*:

- The program will ask you to enter the plaintext. This input needs to be in hexadecimal format. There can be spaces `(a0 e3 11)` or no spaces `(a0e311)` between the byte blocks.
-	If you elected to provide a key, it will ask you for the key next. This needs to be in the same format as the plaintext. The program will also verify that the key entered matches the key length specified.

*CBC, CFB, OFB*:

- If you elected to provide an IV, it will ask you for the IV next. This needs to be in the same format as the plaintext. The program will also verify that the IV entered matches the block length of 16 bytes.

*CTR*:

- If you elected to provide a nonce, it will ask you for the nonce next. This needs to be in the same format as the plaintext. The program will also verify that the nonce entered matches the ctr mode nonce size of 8 bytes.

The program will output the ciphertext as well as the key if a random key was used and the IV/nonce if that was generated as well. If an encryption error occured, the program will only inform you that an error occured.

**Decryption**: 

*All Modes*:

- The program will ask you to enter the padded ciphertext. This input needs to be in hexadecimal format. There can be spaces `(a0 e3 11)` or no spaces `(a0e311)` between the byte blocks.
-	The program will ask you for the key next. This needs to be in the same format as the ciphertext. The program will also verify that the key entered matches the key length specified.

*CBC, CFB, OFB*:

- The program will ask you for the IV next. This needs to be in the same format as the ciphertext. The program will also verify that the IV entered matches the block length of 16 bytes.

*CTR*:

- The program will ask you for the nonce next. This needs to be in the same format as the ciphertext. The program will also verify that the nonce entered matches the CTR mode nonce size of 8 bytes.

The program will output plaintext with the padding removed. If a decryption error occured, the program will only inform you that an error occured.


### Running tests:

Included are 2 types of tests provided by the NIST Cryptographic Algorithm Validation Program. These are included in the NIST folder, which is separate from the main AES implementation. They are the AES KAT (Known Answer Test) vectors as well as AES MMT (Mulitblock Message Test) vectors. There are tests for ECB, CBC, CFB in 128 bit mode, and OFB.

For information about CTR mode testing, see the project report, section 2.7 Implementation Validation

To run these tests, your computer needs Python 3.6 or greater installed and the program needs to be compiled (see above).

First, copy the main executable to the NIST directory.

Next, execute the main.py script in the NIST directory with python3 main.py

For each test, it will inform you how many of them passed out of how many total tests there were.

At the end, it will give you the total number of tests passed out of the total number of tests given. This should be 4276 out of 4276
