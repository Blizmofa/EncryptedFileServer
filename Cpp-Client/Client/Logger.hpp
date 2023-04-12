/*
* Custom logger class to use throughout the project.
*/

#pragma once

#include <fstream>
#include <iostream>
#include <string>

constexpr size_t DATE_TIME_BUFFER_SIZE = 80;

class Logger {
private:
	const std::string logFileName = "clientLogs.log";
	const char* DATE_FORMAT = "%Y-%m-%d %X";
	std::ofstream logFile;
	
public:
	/* Class constructor for creating the log file and logger object */
	Logger();
	~Logger();

	/* Method for logging with log types and error codes */
	void LogOutput(const std::string &logType, const std::string &classLogger, const std::string& attachment1, const std::string &logMessage, const std::string& attachment2, const std::string &lastError);

	/* Returns the Current Date and Time */
	std::string getCurrDateAndTime() const;

	// Operator overloading to log only the error message.
	Logger& operator <<(const std::string &str);
};



