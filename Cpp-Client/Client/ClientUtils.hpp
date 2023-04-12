/*
* ClientUtils class for utils methods to use throughout the project.
*/

#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <base64.h>
#include <iomanip>
#include "Logger.hpp"
#include "ProtocolHandler.hpp"

class ClientUtils {
private:
	const std::string classLoggerName = "Client Utils";
	Logger* clientUtilsLogger;

public:
	
	/* Class Constructor and Destructor */
	ClientUtils();
	~ClientUtils();

	/* Returns the server ip address */
	std::string getIP(std::vector<std::string> vec);

	/* Returns the server port number */
	size_t getPort(std::vector<std::string> vec);

	/* Parse file content acoording to a given pattern */
	size_t getPatternIndex(std::vector<std::string> vec, const std::string pattern);

	/* Validates length */
	bool lengthValidation(const std::string &str, size_t length);

	/* Return true if a given filePath exists, false otherwise */
	bool checkIfFileExists(const std::string& fileName);

	/* Validates string lengthand copying it to the given buffer, to avoid buffer overflow */
	void validateLengthBeforePacking(const std::string& str, const size_t size, uint8_t* const buffer);

	/* Convert a given bytes buffer to a string hex */
	std::string bytesToHex(const uint8_t* buffer, size_t length) const;

	/* Convert a given hex string to bytes */
	std::vector<uint8_t> hexToBytes(const std::string& hexString) const;

	/* Parse a given bytes buffer to a number */
	unsigned long long parseStringBuffer(const uint8_t* buffer, const size_t size);

	/* Validates a given vector index to avoid vector subscript exception */
	bool validateVectorIndex(std::vector<std::string> vec, const size_t index);

	/* Validates a given connection credentials */
	bool validateConnectionCredentials(const size_t port, const std::string& ip);

private:

	/* Auxiliary method to validate the bounds of a given port number */
	bool validatePortRange(const size_t port) const;

	/* Auxiliary method to validate a given ip address */
	bool validateIPAddress(const std::string& ip) const;

};
