import os
import subprocess
from subprocess import PIPE
from pathlib import Path

# Runs a single test through the program
def run_test(mode, key, iv, plaintext, expected_out):
    # Command to run the executable in encrypt mode
    # str(len(key)*4) is because the key is encoded in hex, with 4 bits per character
    # We multiply by 4 to get the number of bits in the key
    command = ['./main','enc',mode,'-k',str(len(key)*4), '-iv']
    
    # Execute the command and wait for it to finish
    # We send the output to a pipe so we can read the output
    # Send the plaintext, key and iv as input
    proc = subprocess.run(command, stdout=PIPE, input=bytes(str(plaintext) + "\n" + str(key) + "\n" + str(iv) + "\n", "UTF-8"))

    # The process failing is no good
    if proc.returncode != 0:
        return False
    
    # Convert the output from bytes to a string
    output = proc.stdout.decode('utf-8')
    # Find the position of the ciphertext and remove the unnecessary parts
    idx = output.find("CIPHERTEXT: ")
    ciphertxt = output[idx + 12: idx + 12 + int((len(plaintext) + 32)*(3/2))]
    ciphertxt = ciphertxt.replace(" ", "").lower()
    
    # Compare the ciphertext
    if ciphertxt[:len(expected_out)] != expected_out:
    	return False
    	
    # Run it in the reverse direction
    command = ['./main','dec',mode, str(len(key)*4), '-iv']
    proc = subprocess.run(command, stdout=PIPE, input=bytes(str(ciphertxt) + "\n" + str(key) + "\n" + str(iv) + "\n", "UTF-8"))

    if proc.returncode != 0:
        return False

    
    output = proc.stdout.decode('utf-8')
    idx = output.find("DECRPYTED PLAINTEXT: ")
    ptx = output[idx + 21: idx + 21 + int((len(plaintext))*(3/2))]
    ptx = ptx.replace(" ", "").lower()
    
    
    # Compare the plaintext
    if ptx[:len(plaintext)] != plaintext:
    	return False
    
    return True

# Runs all of the encrypt tests contained in a file
def run_test_file(filename):
    num_tests = 0
    failed_tests = 0

    test_name = os.path.basename(filename)
    # Ignore all of the CFB tests that are not the 128 bit mode
    if test_name.startswith("CFB"):
        if not test_name.startswith("CFB128"):
            return

    test_name = test_name[:3]

    test_file = open(filename, "r", encoding="utf-8", newline='\r\n')

    seen_encrypt = False
    while test_file:
        line = test_file.readline()
        line = line.strip()
	
	# All of the text before [ENCRYPT] is not important
        if not seen_encrypt:
            if line.startswith("[ENCRYPT]"):
                seen_encrypt = True
        # We can't run the decryption way since it is not padded
        elif line.startswith("[DECRYPT]"):
            break
        # This line is the start of a test
        elif line.startswith("COUNT"):
            # ECB is a special case since there is no IV
            if test_name.startswith("ECB"):
                key = test_file.readline()[6:-2]
                # Just set iv to nothing
                iv = ""
                plaintext = test_file.readline()[12:-2]
                exp_out = test_file.readline()[13:-2]
            else:
                key = test_file.readline()[6:-2]
                iv = test_file.readline()[5:-2]
                plaintext = test_file.readline()[12:-2]
                exp_out = test_file.readline()[13:-2]

            if not run_test(test_name, key, iv, plaintext, exp_out):
                failed_tests += 1
            num_tests += 1

    print("Passed {0} out of {1}".format(num_tests - failed_tests, num_tests))


testDirectory = "./KAT"

for entry in Path(testDirectory).iterdir():
    print(entry.name)
    run_test_file(testDirectory + "/" + entry.name)

