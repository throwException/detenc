# detenc

A command line tool that performs deterministic encryption of an input file to an output file

Usage is: `detenc <command> <keyfile> <inputfile> <outputfile>`

The command is either `enc` oder `dec`.

The key file has to contain a cryptographic key of 64 hex bytes.

One half of the key (256 bits) will be used to create the IV as a CMAC with AES-256-CBC over the file contents.

The other half of the key is used as encryption key for the file contents using AES-256-CTR.

Note that this encryption scheme cannot be secure under chosen plaintext attack a specific plaintext will always generate the same ciphertext. This can allow an attacker to identify known files. This is not a bug, but a design decision for this utility and MUST be taken into account when using it.

I have not done a formal security proof and do NOT claim this scheme is as secure as AES-SIV. The reason I implemented it is to allow encryption of larger files as the implementation of AES-SIV in libcrypto only allows for one update.

The scheme also does not provide any integrity which is also a design choice I made for a specific use case.

