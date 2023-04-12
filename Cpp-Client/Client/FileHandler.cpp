/*
* File Handler Class implementation.
*/

#include "FileHandler.hpp"

FileHandler::FileHandler() {
	
	file = new std::fstream;
	fileLogger = new Logger();
	utils = new ClientUtils();
}

FileHandler::~FileHandler() {
	
	delete file;
	delete fileLogger;
	delete utils;
}

void FileHandler::createFile(const std::string& filePath) {

	if (!this->utils->checkIfFileExists(filePath.c_str())) {

		this->file->open(filePath.c_str(), std::ios::out);

		if (this->file->is_open()) {

			this->fileLogger->LogOutput("INFO", classLoggerName, filePath.c_str(), "has been created successfully.", "", "");
		}
	}
	else {

		this->fileLogger->LogOutput("INFO", classLoggerName, filePath.c_str(), "already exists.", "", "");
	}

	this->file->close();
}

void FileHandler::appendToFile(const std::string& filePath, const std::string& lineToAdd) {
	
	std::string line = lineToAdd;
	line.append("\n");

	this->file->open(filePath.c_str(), std::ios::app);

	if (this->file->is_open()) {

		this->file->write(line.c_str(), line.size());
		this->fileLogger->LogOutput("INFO", classLoggerName, lineToAdd.c_str(), "added successfully to file", filePath.c_str(), "");
	}
	else {

		this->fileLogger->LogOutput("ERROR", classLoggerName, "Unable to open file", filePath.c_str(), "", "");
	}

	this->file->close();
}

std::vector<std::string> FileHandler::getFileContent(const std::string& filePath) const {

	std::string line{ NULL };
	std::vector<std::string> fileLines;
	this->file->open(filePath.c_str(), std::ios::in);

	if (this->file->is_open()) {

		while (std::getline(*file, line)) {

			if (line.size() > 0) {

				fileLines.emplace_back(line);
			}
		}
		this->fileLogger->LogOutput("INFO", classLoggerName, "Retreived file lines successfully from", filePath.c_str(), "", "");
	}
	else {

		this->fileLogger->LogOutput("ERROR", classLoggerName, "Unable to open file", filePath.c_str(), "", "");
	}

	this->file->close();
	return fileLines;
}

bool FileHandler::isLineExists(const std::string& filePath, const size_t lineNumber) {

	std::vector<std::string> lines;
	lines = this->getFileContent(filePath.c_str());
	bool flag = false;

	if (!lines[lineNumber].empty()) {
		flag = true;
	}

	lines.clear();
	return flag;
}

size_t FileHandler::getFileNumOfLines(const std::string& filePath) const {

	std::string line{ NULL };
	size_t lines = { 0 };
	this->file->open(filePath.c_str(), std::ios::in);

	if (this->file->is_open()) {

		while (this->file->peek() != EOF) {

			std::getline(*file, line);
			lines++;
		}
	}
	else {

		this->fileLogger->LogOutput("ERROR", classLoggerName, "Unable to count nubmer of lines, can't open file", filePath.c_str(), "", "");
	}

	this->file->close();
	return lines;
}

size_t FileHandler::getFileSize(const std::string& filePath) const {

	size_t size = { 0 };
	this->file->open(filePath.c_str(), std::ios::in | std::ios::binary);

	if (this->file->is_open()) {

		try {

			this->file->seekg(0, std::ios::end);
			this->fileLogger->LogOutput("INFO", classLoggerName, "Retreived", filePath.c_str(), "size successfully.", "");
			size = this->file->tellg();
		}

		catch (const std::exception& e) {

			this->fileLogger->LogOutput("ERROR", classLoggerName, "Unable to calculate file size, Error:", e.what(), "", "");
			size = 0;
		}
	}
	else {

		this->fileLogger->LogOutput("ERROR", classLoggerName, "Unable to open file", filePath.c_str(), "", "");
	}
	this->file->close();
	return size;
}


uint32_t FileHandler::getFileCRC(const std::string& filePath) const {

	std::fstream crcFile;
	crcFile.open(filePath.c_str(), std::ios::in | std::ios::binary);

	try {
		char buffer[CRC_BUFFER_SIZE];
		boost::crc_32_type result;

		do {

			crcFile.read(buffer, sizeof(buffer));
			result.process_bytes(buffer, crcFile.gcount());

		} while (crcFile);

		if (crcFile.eof()) {

			this->fileLogger->LogOutput("INFO", classLoggerName, "Calculated CRC for file", filePath.c_str(), "successfully.", "");
			crcFile.close();
			return result.checksum();
		}	
	}
	catch (const std::exception& e) {

		this->fileLogger->LogOutput("ERROR", classLoggerName, "Unable to calculate file CRC, Error:", e.what(), "", "");
		crcFile.close();
	}
}

std::vector<uint8_t> FileHandler::getFileContentInBytes(const std::string& filePath) const {

	std::ifstream input(filePath.c_str(), std::ios::binary);
	size_t size = this->getFileSize(filePath.c_str());
	std::vector<uint8_t> plain(size);

	if (!input.read(reinterpret_cast<char*>(plain.data()), size)) {

		this->fileLogger->LogOutput("ERROR", classLoggerName, "unable to read file", filePath.c_str(), "", "");
	}

	input.close();
	return plain;
}

std::string FileHandler::createEncryptedFile(const std::string& filePath, const std::string& encryptedContent) {

	std::string newFileName = filePath + encryptedFileSuffix;

	this->file->open(newFileName, std::ios::out | std::ios::binary);

	if (this->file->is_open()) {

		try {

			this->file->write(encryptedContent.c_str(), encryptedContent.length());
			this->fileLogger->LogOutput("INFO", classLoggerName, "Created encrypted file", newFileName.c_str(), "successfully.", "");
		}
		catch (const std::exception& e) {

			this->fileLogger->LogOutput("ERROR", classLoggerName, "Unable to create encrypted file", newFileName.c_str(), ", Error:", e.what());
		}
	}

	this->file->close();
	return newFileName;
}

void FileHandler::deleteFile(const std::string & filePath) const {

	if (std::remove(filePath.c_str()) == 0) {

		this->fileLogger->LogOutput("INFO", classLoggerName, "Deleted", filePath.c_str(), "successfully.", "");

	}
	else {

		this->fileLogger->LogOutput("ERROR", classLoggerName, "Unable to delete file", filePath.c_str(), ".", "");
	}
}

std::string FileHandler::getFilePath(const std::string & fileName) const {

	char fullPath[FILE_NAME_SIZE];
	DWORD pathLength = GetFullPathNameA(fileName.c_str(), FILE_NAME_SIZE, fullPath, nullptr);

	if (pathLength > 0 && pathLength < FILE_NAME_SIZE) {
		return std::string(fullPath);
	}
	else {
		throw std::runtime_error("Unable to retrieve file full path");
	}
}