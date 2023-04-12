/*
* AES Wrapper to generate symmetric key, encrypt and decrypt given texts with AES MODE_CBC
*/

#pragma once

#include <string>

class AESWrapper
{
public:
	static const unsigned int DEFAULT_KEYLENGTH = 16;

private:
	unsigned char _key[DEFAULT_KEYLENGTH];
	AESWrapper(const AESWrapper& aes);

public:

	/* Generates symmetric key according to a fixed length */
	static unsigned char* GenerateKey(unsigned char* buffer, unsigned int length);

	/* Class Constructors and destructor */
	AESWrapper();
	AESWrapper(const unsigned char* key, unsigned int size);
	~AESWrapper();

	/* Returns the symmetric key */
	const unsigned char* getKey() const;

	/* Encrypts a given text */
	std::string encrypt(const char* plain, unsigned int length);

	/* Decrypts a given text */
	std::string decrypt(const char* cipher, unsigned int length);
};

