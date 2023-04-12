/*
* RSA Public/Private Wrappers to generate keys, encrypt and decrypt given texts.
*/

#pragma once

#include <osrng.h>
#include <rsa.h>
#include <string>

class RSAPublicWrapper {

public:
	static const unsigned int KEYSIZE = 160;
	static const unsigned int BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PublicKey _publickey;

	/* Copy Constructor and operator overloading to support it */
	RSAPublicWrapper(const RSAPublicWrapper& other);
	RSAPublicWrapper& operator=(const RSAPublicWrapper& other);

public:

	/* Class Constructors and Destructor */
	RSAPublicWrapper(const char* key, unsigned int length);
	RSAPublicWrapper(const std::string & other);
	~RSAPublicWrapper();

	/* Return the generated RSA public key */
	std::string getPublicKey() const;
	char* getPublicKey(char* keyout, unsigned int length) const;

	/* Encrypts a given text */
	std::string encrypt(const std::string& text);
	std::string encrypt(const char* text, unsigned int length);

};

class RSAPrivateWrapper {

public:
	static const unsigned int BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PrivateKey _privatekey;

	/* Copy Constructor and operator overloading to support it */
	RSAPrivateWrapper(const RSAPrivateWrapper& other);
	RSAPrivateWrapper& operator=(const RSAPrivateWrapper& other);

public:

	/* Class Constructors and Destructor */
	RSAPrivateWrapper();
	RSAPrivateWrapper(const char* key, unsigned int length);
	RSAPrivateWrapper(const std::string& other);
	~RSAPrivateWrapper();

	/* Return the generated RSA private key */
	std::string getPrivateKey() const;
	char* getPrivateKey(char* keyout, unsigned int length) const;

	/* Return the generated RSA public key */
	std::string getPublicKey() const;
	char* getPublicKey(char* keyout, unsigned int length) const;

	/* Decrypts a given text */
	std::string decrypt(const std::string& cipher);
	std::string decrypt(const char* cipher, unsigned int length);
};


