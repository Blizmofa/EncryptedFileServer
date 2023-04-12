/*
* RSA Public/Private Wrappers implementation.
*/

#include "RSAWrapper.hpp"


// Public Wrapper
RSAPublicWrapper::RSAPublicWrapper(const char* key, unsigned int length) {

	CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(key), length, true);
	this->_publickey.Load(ss);
}

RSAPublicWrapper::RSAPublicWrapper(const std::string& other) {

	CryptoPP::StringSource ss(other, true);
	this->_publickey.Load(ss);
}

RSAPublicWrapper::~RSAPublicWrapper() {
}

std::string RSAPublicWrapper::getPublicKey() const {

	std::string key;
	CryptoPP::StringSink ss(key);
	_publickey.Save(ss);
	return key;
}

char* RSAPublicWrapper::getPublicKey(char* keyout, unsigned int length) const {

	CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
	_publickey.Save(as);
	return keyout;
}

std::string RSAPublicWrapper::encrypt(const std::string& text) {

	std::string cipher;
	CryptoPP::RSAES_OAEP_SHA_Encryptor e(_publickey);
	CryptoPP::StringSource ss(text, true, new CryptoPP::PK_EncryptorFilter(_rng, e, new CryptoPP::StringSink(cipher)));
	return cipher;
}

std::string RSAPublicWrapper::encrypt(const char* text, unsigned int length) {

	std::string cipher;
	CryptoPP::RSAES_OAEP_SHA_Encryptor e(_publickey);
	CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(text), length, true, new CryptoPP::PK_EncryptorFilter(_rng, e, new CryptoPP::StringSink(cipher)));
	return cipher;
}

// Private Wrapper
RSAPrivateWrapper::RSAPrivateWrapper() {

	this->_privatekey.Initialize(_rng, BITS);
}

RSAPrivateWrapper::RSAPrivateWrapper(const char* key, unsigned int length) {

	CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(key), length, true);
	this->_privatekey.Load(ss);
}

RSAPrivateWrapper::RSAPrivateWrapper(const std::string& other) {

	CryptoPP::StringSource ss(other, true);
	this->_privatekey.Load(ss);
}

RSAPrivateWrapper::~RSAPrivateWrapper() {}

std::string RSAPrivateWrapper::getPrivateKey() const {

	std::string key;
	CryptoPP::StringSink ss(key);
	this->_privatekey.Save(ss);
	return key;
}

char* RSAPrivateWrapper::getPrivateKey(char* keyout, unsigned int length) const {

	CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
	_privatekey.Save(as);
	return keyout;
}

std::string RSAPrivateWrapper::getPublicKey() const {

	CryptoPP::RSAFunction publicKey(_privatekey);
	std::string key;
	CryptoPP::StringSink ss(key);
	publicKey.Save(ss);
	return key;
}

char* RSAPrivateWrapper::getPublicKey(char* keyout, unsigned int length) const {

	CryptoPP::RSAFunction publickey(_privatekey);
	CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
	publickey.Save(as);
	return keyout;
}

std::string RSAPrivateWrapper::decrypt(const std::string& cipher) {

	std::string decrypted;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(this->_privatekey);
	CryptoPP::StringSource ss(cipher, true, new CryptoPP::PK_DecryptorFilter(this->_rng, d, new CryptoPP::StringSink(decrypted)));
	return decrypted;
}

std::string RSAPrivateWrapper::decrypt(const char* cipher, unsigned int length) {

	std::string decrypted;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privatekey);
	CryptoPP::StringSource ss_cipher(reinterpret_cast<const CryptoPP::byte*>(cipher), length, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
	return decrypted;
}