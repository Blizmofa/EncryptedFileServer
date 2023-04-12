/*
* File Handler Class for working with files throughout the project.
*/

#pragma once

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <boost/crc.hpp>
#include <Windows.h>
#include "Logger.hpp"
#include "ClientUtils.hpp"
#include "AESWrapper.hpp"
#include "ProtocolHandler.hpp"

constexpr size_t CRC_BUFFER_SIZE = 4096;

class FileHandler {

private:
	const std::string classLoggerName = "FileHandler";
	const std::string encryptedFileSuffix = ".enc";
	std::fstream* file;
	Logger *fileLogger;
	ClientUtils* utils;


public:
	FileHandler();
	~FileHandler();

	/* Creates file according to a given name and data */
	void createFile(const std::string & filePath);

	/* Add a given line to the end of the file */
	void appendToFile(const std::string & filePath, const std::string &lineToAdd);

	/* Returns all file lines as a vector */
	std::vector<std::string> getFileContent(const std::string & filePath) const;

	/* Check if a line exists in a given file */
	bool isLineExists(const std::string& filePath, const size_t lineNumber);

	/* Return a given file number of lines */
	size_t getFileNumOfLines(const std::string& filePath) const;
	
	/* Returns the file size in bytes */
	size_t getFileSize(const std::string & filePath) const;

	/* Returns the file CRC value */
	uint32_t getFileCRC(const std::string& filePath) const;

	/* Reads a given file content into byte vector buffer */
	std::vector<uint8_t> getFileContentInBytes(const std::string& filePath) const;

	/* Return a string representation of a new created encrypted file path */
	std::string createEncryptedFile(const std::string& filePath, const std::string& encryptedContent);

	/* Delete a file according to a given file path */
	void deleteFile(const std::string& filePath) const;

	/* Returns the given file name full path */
	std::string getFilePath(const std::string& fileName) const;
};

