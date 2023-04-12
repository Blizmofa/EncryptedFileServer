/*
* Base64Wrapper Class to Encode/Decode string into Base64 format.
*/

#pragma once

#include <string>
#include <base64.h>

class Base64Wrapper {
public:

	/* Encodes a given string to Base64 format */
	static std::string encode(const std::string& str);

	/* Decodes a given Base64 string */
	static std::string decode(const std::string& str);
};


