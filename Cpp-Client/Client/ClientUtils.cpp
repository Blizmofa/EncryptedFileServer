/*
* ClientUtils Class implementation.
*/

#include "ClientUtils.hpp"

ClientUtils::ClientUtils() {

	clientUtilsLogger = new Logger();
};

ClientUtils::~ClientUtils() {
	delete clientUtilsLogger;
};


std::string ClientUtils::getIP(std::vector<std::string> vec) {

	std::string ip{ NULL };

	size_t index = this->getPatternIndex(vec, ":");
	size_t pos = vec.at(index).find(":");
	ip = vec.at(index).substr(0, pos);

	return ip;
}

size_t ClientUtils::getPort(std::vector<std::string> vec) {

	size_t index = this->getPatternIndex(vec, ":");
	size_t pos = vec.at(index).find(":");
	size_t port = std::stoi(vec.at(index).substr(pos + 1));

	return port;
}

size_t ClientUtils::getPatternIndex(std::vector<std::string> vec, const std::string pattern) {

	size_t index{ 0 };
	auto it = std::find(vec.begin(), vec.end(), pattern);

	if (it != vec.end()) {

		index = it - vec.begin();
	}

	return index;
}

bool ClientUtils::lengthValidation(const std::string &str, size_t length) {

	if (str.length() >= length) {

		std::cout << "   - " << str.c_str() << " can be only " << length << " bytes long. " << std::endl;
		return false;
	}
	else {

		std::cout << "   - " << str.c_str() << " is of valid length." << std::endl;
		return true;
	}
}

bool ClientUtils::checkIfFileExists(const std::string& fileName) {

	std::ifstream inFile(fileName);
	return inFile.good();
}

void ClientUtils::validateLengthBeforePacking(const std::string& str, const size_t size, uint8_t* const buffer) {

	if (this->lengthValidation(str, size)) {

		memcpy(buffer, str.data(), str.length());
		this->clientUtilsLogger->LogOutput("INFO", classLoggerName, str.c_str(), "is of valid length.", "", "");
	}
	else {

		this->clientUtilsLogger->LogOutput("ERROR", classLoggerName, str.c_str(), "length validation failed.", "", "");
	}
}

std::string ClientUtils::bytesToHex(const uint8_t* buffer, size_t length) const {

	std::stringstream ss;
	ss << std::hex << std::setfill('0');

	for (size_t i = 0; i < length; i++) {

		ss << std::setw(2) << static_cast<unsigned>(buffer[i]);
	}

	this->clientUtilsLogger->LogOutput("INFO", classLoggerName, "Converted bytes:", reinterpret_cast<const char*>(buffer), "to hex:", ss.str());
	return ss.str();
}

std::vector<uint8_t> ClientUtils::hexToBytes(const std::string& hexString) const {

	std::vector<uint8_t> bytes;

	for (std::size_t i = 0; i < hexString.length(); i += 2) {

		std::string byteString = hexString.substr(i, 2);
		uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
		bytes.emplace_back(byte);
	}

	this->clientUtilsLogger->LogOutput("INFO", classLoggerName, "Converted hex:", hexString.c_str(), "to bytes:", reinterpret_cast<const char*>(bytes.data()));
	return bytes;
}

unsigned long long ClientUtils::parseStringBuffer(const uint8_t* buffer, const size_t size) {

	unsigned long long num = { 0 };
	std::string str(reinterpret_cast<const char*>(buffer), size);

	try {

		num = std::stoll(str);
		this->clientUtilsLogger->LogOutput("INFO", classLoggerName, "Parsed bytes:", reinterpret_cast<const char*>(buffer), "to number:", std::to_string(num));
	}
	catch (const std::exception& e) {

		this->clientUtilsLogger->LogOutput("ERROR", classLoggerName, "Unable to parsed bytes:", reinterpret_cast<const char*>(buffer), "Error:", e.what());
	}
	return num;
}

bool ClientUtils::validateConnectionCredentials(const size_t port, const std::string& ip) {

	if (this->validatePortRange(port) && this->validateIPAddress(ip)) {

		this->clientUtilsLogger->LogOutput("INFO", classLoggerName, ip.c_str(), "and", std::to_string(port), "validation success.");
		return true;
	}

	this->clientUtilsLogger->LogOutput("ERROR", classLoggerName, ip.c_str(), "and", std::to_string(port), "validation failure.");
	return false;
}

bool ClientUtils::validateVectorIndex(std::vector<std::string> vec, const size_t index) {

	if (vec[index].empty()) {
		return false;
	}

	return true;
}

bool ClientUtils::validatePortRange(const size_t port) const {

	if (port < PORT_LOWER_BOUND || port > PORT_UPPER_BOUND) {

		return false;
	}

	return true;
}

bool ClientUtils::validateIPAddress(const std::string& ip) const {

	// Split the IP address into its components using stringstream and vector
	std::stringstream ss(ip);
	std::string component;
	std::vector<std::string> components;

	while (std::getline(ss, component, '.')) {

		components.push_back(component);
	}

	// Check if the IP address has 4 components
	if (components.size() != IP_DEFAULT_NUM_OF_COMPONENTS) {

		return false;
	}

	// Check if each component is a number within the valid range
	for (const auto& component : components) {

		if (component.empty() || component.size() > IP_DEFAULT_NUM_OF_COMPONENTS - 1 || !std::all_of(component.begin(), component.end(), ::isdigit)) {

			return false;
		}

		int num = std::stoi(component);

		if (num < IP_LOWER_BOUND || num > IP_UPPER_BOUND) {
			return false;
		}
	}

	return true;
}

