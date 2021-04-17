To run the NIST AES validation vectors:
Compile the main program using the make command
Copy the executable to this directory
Create a new folder called KAT in this directory
Download the AES KAT Vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip
Download the AES MMT Vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmmt.zip
Unzip the zips and put the contents into the KAT directory created earlier removing any files that do not have the .rsp extension
Execute the main.py script with python3 main.py

For each test, it will inform you how many of them passed over how many tests there were