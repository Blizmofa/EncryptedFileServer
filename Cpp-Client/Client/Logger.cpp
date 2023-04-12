/*
* Logger Class implementation.
*/

#include "Logger.hpp"

Logger::Logger() {

	if (!this->logFile) {

		this->logFile.open(this->logFileName, std::ios_base::out);

		if (this->logFile.is_open()) {

			this->logFile << "[" << this->getCurrDateAndTime() << "]" << " - " << "[INFO] - [Logger] ----- " << this->logFileName << " has been created successfully.";
		}
	}
}

Logger::~Logger() { 

	this->logFile.close();
}

void Logger::LogOutput(const std::string& logType, const std::string& classLogger, const std::string& attachment1, const std::string& logMessage, const std::string& attachment2, const std::string& lastError) {

	this->logFile.open(this->logFileName.c_str(), std::ios_base::app | std::ios_base::out);

	if (this->logFile.is_open()) {

		this->logFile << "[" << this->getCurrDateAndTime() << "]" << " - [" << logType << "] - " << "[" << classLogger << "] ----- " << attachment1 << " " << logMessage << " " << attachment2 << " " << lastError << "\n";
	}

	this->logFile.close();
}

std::string Logger::getCurrDateAndTime() const {

	time_t current = time(NULL);
	struct tm time_struct;
	char date_time_buff[DATE_TIME_BUFFER_SIZE];

	localtime_s(&time_struct, &current);
	strftime(date_time_buff, sizeof(date_time_buff), DATE_FORMAT, &time_struct);

	return date_time_buff;
}


Logger& Logger::operator <<(const std::string &str) {

	this->logFile << "\n" << this->getCurrDateAndTime() << " - " << str << "\n";
	return *this;
}