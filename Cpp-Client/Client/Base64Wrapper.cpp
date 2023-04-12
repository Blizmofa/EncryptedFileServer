/*
* Base64Wrapper Class implementation.
*/

#include "Base64Wrapper.hpp"

std::string Base64Wrapper::encode(const std::string& str) {

	std::string encoded;
	CryptoPP::StringSource ss(str, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded)));
	return encoded;
}

std::string Base64Wrapper::decode(const std::string& str) {

	std::string decoded;
	CryptoPP::StringSource ss(str, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
	return decoded;
}