/*
* Client Class implementation.
*/

#include "Client.hpp"

Client::Client() : serverInfo{ DEFAULT_INITIALIZE_VALUE }, clientFileHandler{nullptr}, rsaPrivateKey { nullptr } {

	rsaPrivateKey = new RSAPrivateWrapper();
	utils = new ClientUtils();
	clientLogger = new Logger();
	clientFileHandler = new FileHandler();

	if (!Socket::init()) {

		std::cout << "[!] Unable to Initialize WinSock." << std::endl;
		this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to initialize WinSock, Error #:", std::to_string(this->GetLastError()), "", "");
	}
	// Socket has been initialized successfully
	else {
		
		this->clientSocket = socket(AF_INET, SOCK_STREAM, 0);

		if (this->clientSocket == INVALID_SOCKET || this->clientSocket < 0) {

			this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to open socket, Error #:", std::to_string(this->GetLastError()), "", "");
			Socket::cleanup();
		}
		else {

			this->clientLogger->LogOutput("INFO", classLoggerName, "Socket has been created successfully.", "", "", "");
		}
	}
}

Client::~Client() {

	this->Disconnect();
	Socket::cleanup();
	delete rsaPrivateKey;
	delete clientLogger;
	delete utils;
	delete clientFileHandler;
}

bool Client::Connect(const std::string &ip_address, const size_t port) {

	/* Define server info structure */
	ZeroMemory(&serverInfo, sizeof(this->serverInfo));
	this->serverInfo.sin_family = AF_INET;
	this->serverInfo.sin_port = htons(port); // for Little/Big endian byte order
	this->serverInfo.sin_addr.S_un.S_addr = inet_addr((ip_address).c_str()); // for ip address conversion from text to binary

	std::cout << "[+] Esablishing connection to server..." << std::endl;
	size_t connectResult = connect(this->clientSocket, (sockaddr*)&this->serverInfo, sizeof(serverInfo));

	if (connectResult == SOCKET_ERROR || connectResult != 0) {

		std::cout << "   - Connection to " << ip_address << ":" << port << " has failed." << std::endl;
		this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to connect to server, Error #:", std::to_string(this->GetLastError()), "", "");
		Socket::closeSocket(this->clientSocket);
		Socket::cleanup();
		return false;
	}
	else {

		std::stringstream connection; 
		connection << ip_address << ":" << port;
		std::cout << "[+] Connected to " << connection.str() << " successfully." << std::endl;
		this->clientLogger->LogOutput("INFO", classLoggerName, "******************** New Connection ********************", "", "", "");
		this->clientLogger->LogOutput("INFO", classLoggerName, "Connected to server", connection.str(), "successfully.", "");
		return true;
	}
}

void Client::Disconnect() {
	
	Socket::closeSocket(this->clientSocket);
	std::cout << "[+] Disconnected from server." << std::endl;
	this->clientLogger->LogOutput("INFO", classLoggerName, "Disconnected from server successfully.", "", "", "");
	Socket::cleanup();
}

bool Client::Shutdown() {

	size_t shutdownResult = shutdown(this->clientSocket, SD_SEND);

	if (shutdownResult == SOCKET_ERROR) {

		this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to shutdown the connection, Error #:", std::to_string(this->GetLastError()), "", "");
		Socket::closeSocket(this->clientSocket);
		Socket::cleanup();
		return false;
	}
	else {

		std::cout << "[+] Connection has been shutdown successfully." << std::endl;
		this->clientLogger->LogOutput("INFO", classLoggerName, "Connection has been shutdown successfully.", "", "", "");
		return true;
	}
}

std::string Client::GetClientUsername(const std::string &mainFileName, const std::string &backupFileName) const {

	size_t index{ 0 };
	std::string username{NULL};
	std::vector<std::string> lines;

	if (this->utils->checkIfFileExists(mainFileName.c_str())) {

		lines = this->clientFileHandler->getFileContent(mainFileName.c_str());
		index = this->utils->getPatternIndex(lines, " ");
		username = lines.at(index);
		this->clientLogger->LogOutput("INFO", classLoggerName, "Found valid username in file:", mainFileName.c_str(), "", "");
	}
	else if (this->utils->checkIfFileExists(backupFileName)) {

		lines = this->clientFileHandler->getFileContent(backupFileName.c_str());
		index = this->utils->getPatternIndex(lines, " ");
		username = lines.at(index);
		this->clientLogger->LogOutput("INFO", classLoggerName, "Found valid username in file.", backupFileName.c_str(),"", "");
	}
	else {

		this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to find valid username.", "", "", "");
	}

	return username;
}

bool Client::SendPacket(const uint8_t* const buffer, const size_t size) const {
	
	size_t bytesLeft = size;
	const uint8_t* ptr = buffer;

	while (bytesLeft > 0) {

		uint8_t tempBuffer[PACKET_MAX_BUFFER] = { 0 };
		const size_t bytesToSend = (bytesLeft > PACKET_MAX_BUFFER) ? PACKET_MAX_BUFFER : bytesLeft; // To avoid buffer overflow

		memcpy(tempBuffer, ptr, bytesToSend);

		const size_t sendResult = send(this->clientSocket, reinterpret_cast<const char*>(tempBuffer), bytesLeft, 0);

		if (sendResult == 0) {

			return false;
		}

		ptr += sendResult;
		bytesLeft = (bytesLeft < sendResult) ? 0 : (bytesLeft - sendResult); // For positive value validation

	}

	return true;
}

bool Client::sendFileContent(const std::string& filePath, const size_t size) const {

	size_t  bytesSent = 0;
	size_t totalBytesSent = 0;
	std::vector<uint8_t> content;

	try {

		content.resize(size);
	}
	catch (const std::exception& e) {

		this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to resize vector buffer.", e.what(), "", "");
	}

	// Reading file to buffer and send it's content
	std::ifstream file(filePath.c_str(), std::ios::binary);
	if (!file) {

		this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to open file.", filePath.c_str(), "", "");
		return false;
	}

	// Reading file content to buffer in chunks
	while (file.read(reinterpret_cast<char*>(content.data()), size)) {

		bytesSent = send(this->clientSocket, reinterpret_cast<const char*>(content.data()), size, 0);

		if (bytesSent == SOCKET_ERROR) {

			this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to send file to server,  Error #:", filePath.c_str(), std::to_string(this->GetLastError()), "");
			closesocket(this->clientSocket);
			Socket::cleanup();
			return false;
		}

		totalBytesSent += bytesSent;
	}

	// For the file content leftovers
	size_t remainingBytes = file.gcount();
	if (remainingBytes > 0) {

		bytesSent = send(this->clientSocket, reinterpret_cast<const char*>(content.data()), size, 0);

		if (bytesSent == SOCKET_ERROR) {

			this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to send file to server,  Error #:", filePath.c_str(), std::to_string(this->GetLastError()), "");
			closesocket(this->clientSocket);
			Socket::cleanup();
			return false;
		}

		totalBytesSent += bytesSent;
	}

	content.clear();
	file.close();
	return true;
}

bool Client::ReceivePacket(uint8_t* const buffer, const size_t size) const {

	size_t bytesLeft = size;
	uint8_t* ptr = buffer;

	while (bytesLeft > 0) {

		uint8_t tempBuffer[PACKET_MAX_BUFFER] = { 0 };
		size_t bytesRead = recv(this->clientSocket, reinterpret_cast<char*>(tempBuffer), PACKET_MAX_BUFFER, 0);

		if (bytesRead > 0) {

			const size_t bytesToCopy = (bytesLeft > bytesRead) ? bytesRead : bytesLeft; // To avoid buffer overflow
			memcpy(ptr, tempBuffer, bytesToCopy);
			ptr += bytesToCopy;
			bytesLeft = (bytesLeft < bytesToCopy) ? 0 : (bytesLeft - bytesToCopy); // For positive value validation

			return true;
		}
		else if (bytesRead == 0) {

			return false;
		}
	}

	return true;
}


void Client::CreateClientFiles(const std::string &connectionDetails, const std::string &clientName, const std::string &filePath) {

	if (!this->utils->checkIfFileExists(ME_INFO)) {

		this->clientFileHandler->createFile(ME_INFO);
		this->clientFileHandler->appendToFile(ME_INFO, clientName);
	}

	if (!this->utils->checkIfFileExists(SERVER_INFO)) {

		this->clientFileHandler->createFile(SERVER_INFO);
		this->clientFileHandler->appendToFile(SERVER_INFO, connectionDetails);
		this->clientFileHandler->appendToFile(SERVER_INFO, clientName);
		this->clientFileHandler->appendToFile(SERVER_INFO, filePath);
	}
}

void Client::HandleRegisterRequest() {

	registerNamePacket request;
	clientIDResponsePayload response;

	std::cout << "[+] Processing registration request..." << std::endl;
	std::vector<std::string> fileLines = clientFileHandler->getFileContent(ME_INFO);
	std::string username = this->GetClientUsername(ME_INFO, SERVER_INFO);

	// Packing registeration request and validate data to avoid buffer overflow
	try {

		this->packRegisterRequest(request, REGISTRATION_REQUEST_CODE, username);
		this->clientLogger->LogOutput("INFO", classLoggerName, "Packed registration request successfully.", "", "", "");

	}
	catch (const std::exception& e) {

		this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to pack registration request, Error: ", e.what(), "", "");
	}

	// Sending request to server
	if (this->SendPacket(reinterpret_cast<const uint8_t* const>(&request), sizeof(request))) {

		std::cout << "   - Sending register request to server." << std::endl;

	}
	else {

		std::cout << SERVER_ERROR_MESSAGE << std::endl;
	}

	// Unapck server response
	if (this->ReceivePacket(reinterpret_cast<uint8_t* const>(&response), sizeof(response))) {

		std::cout << "   - Receiving registration response from server." << std::endl;

		// Check if user already registered according to server response code
		if (response.packet_header.responseCode == REGISTRATION_FAILED_RESPONSE_CODE) {

			
			std::cout << "   - Server: You are already registered." << std::endl;

			// In case ME_INFO file got deleted in runtime
			if (fileLines.size() <= CLIENT_UUID_FILE_INDEX) {

				std::cerr << "   ! " << ME_INFO.c_str() << " file is corrupted, please call support and retrieve your client id." << std::endl;
				this->clientLogger->LogOutput("ERROR", classLoggerName, ME_INFO.c_str(), "file is corrupted, shutting down.", "", "");
				this->Disconnect();
				std::exit(EXIT_FAILURE);

			}
			else {
			
				// Validate to avoid subscript exception
				if (this->utils->validateVectorIndex(fileLines, CLIENT_UUID_FILE_INDEX)) {

					this->clientData.ID.append(fileLines[CLIENT_UUID_FILE_INDEX]);
				}

				// Validate to avoid file duplicates
				if (!this->clientFileHandler->isLineExists(ME_INFO, CLIENT_UUID_FILE_INDEX)) {

					this->clientFileHandler->appendToFile(ME_INFO, clientData.ID.c_str());
				}
			}
			
			this->clientLogger->LogOutput("INFO", classLoggerName, "Registration Failed, client already registered.", "", "", "");
		}
		else if (response.packet_header.responseCode == REGISTRATION_APPROVED_RESPONSE_CODE) {

			// Converting uuid from bytes to hex
			std::cout << "   - Server: Registration approved." << std::endl;
			std::string hexed_uuid = this->utils->bytesToHex(response.ID.ID, sizeof(response.ID.ID));
			std::cout << "   - Server: Your UUID is " << hexed_uuid << "." << std::endl;

			// Updating data structs and files accordinglly
			this->clientLogger->LogOutput("INFO", classLoggerName, "Registration approved by server, client UUID is:", hexed_uuid.data(), "", "");
			this->clientFileHandler->appendToFile(ME_INFO, hexed_uuid);
			this->clientData.ID.append(hexed_uuid);
		}
	}
	else {

		std::cout << SERVER_ERROR_MESSAGE << std::endl;
	}

	// Cleanup
	fileLines.clear();
}

void Client::HandlePubKeyRequest() {

	publicKeyPacket request;
	clientEncryptedKeyResponsePayload response;

	// Generating key pair and update RAM database
	std::cout << "[+] Processing public key request..." << std::endl;
	std::cout << "   - Generating RSA key pair." << std::endl;

	std::string username = this->clientData.username.data();
	const auto pubkey = rsaPrivateKey->getPublicKey();
	this->clientData.RSAPrivateKey = rsaPrivateKey->getPrivateKey();
	std::string encodedKey = Base64Wrapper::encode(rsaPrivateKey->getPrivateKey());

	// Packing public key request and validate data to avoid buffer overflow
	try {

		this->packPublicKeyRequest(request, PUBKEY_REQUEST_CODE, username, pubkey);

		// To avoid key duplicates
		if (this->clientFileHandler->getFileNumOfLines(ME_INFO) <= ME_FILE_MAX_NUMBER_OF_LINES) {

			this->clientFileHandler->appendToFile(ME_INFO, encodedKey.data());
		}
		this->clientLogger->LogOutput("INFO", classLoggerName, "Packed public key request successfully.", "", "", "");

	}
	catch (const std::exception& e) {

		this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to pack public key request, Error: ", e.what(), "", "");
	}

	// Sending request to server
	if (this->SendPacket(reinterpret_cast<const uint8_t* const>(&request), sizeof(request))) {

		std::cout << "   - Sending public key to server." << std::endl;

	}
	else {

		std::cout << SERVER_ERROR_MESSAGE << std::endl;
	}

	// Unapck server response
	if (this->ReceivePacket(reinterpret_cast<uint8_t* const>(&response), sizeof(response))) {

		std::cout << "   - Receiving public key response from server." << std::endl;
	}
	else {

		std::cout << SERVER_ERROR_MESSAGE << std::endl;
	}

	// Decrypting server AES key
	try {

		this->decryptServerAESKey(response.payload.serverEncryptedKey, SERVER_RSA_KEY_SIZE);

	}
	catch (const std::exception& e) {

		this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to decrypt server private key, Error:", e.what(), "", "");
	}
}

void Client::HandleEncryptedFileRequest() {

	EncryptedFilePacket request;
	FileCRCResponse response;

	std::cout << "[+] Processing encrypted file request..." << std::endl;

	// Fetching needed data
	std::vector<std::string> fileLines = clientFileHandler->getFileContent(SERVER_INFO);
	std::string filePath = fileLines[CLIENT_FILE_PATH_FILE_INDEX];
	size_t fileSize = this->clientFileHandler->getFileSize(filePath);

	// Creating encrypted file and validate sizes
	std::cout << "   - Creating encrypted file." << std::endl;
	std::string encryptedContent = this->encryptFileContent(filePath, fileSize);
	std::string encryptedFile = this->clientFileHandler->createEncryptedFile(filePath, encryptedContent);
	this->clientData.filePath.append(filePath.data());
	size_t encryptedSize = this->clientFileHandler->getFileSize(encryptedFile);

	// Packing encrypted file request and validate data to avoid buffer overflow
	try {

		this->packEncryptedFileRequest(request, FILE_REQUEST_CODE, encryptedFile, encryptedSize);
		this->clientLogger->LogOutput("INFO", classLoggerName, "Packed encrypted file request successfully.", "", "", "");

	}
	catch (const std::exception& e) {

		this->clientLogger->LogOutput("ERROR", classLoggerName, "", "Unable to pack encrypted file request, Error: ", e.what(), "");
	}

	// Sending request header to server to adjust sizes
	if (this->SendPacket(reinterpret_cast<const uint8_t* const>(&request), sizeof(request))) {

		std::cout << "   - Sending encrypted file header." << std::endl;

	}
	else {

		std::cout << SERVER_ERROR_MESSAGE << std::endl;
	}

	// Sending file content to server
	if (this->sendFileContent(reinterpret_cast<const char*>(&request.fileName.fileName), request.contentSize)) {

		std::cout << "   - Sending encrypted file content." << std::endl;
	}
	else {

		std::cout << SERVER_ERROR_MESSAGE << std::endl;
	}

	// Unapck server response
	if (this->ReceivePacket(reinterpret_cast<uint8_t* const>(&response), sizeof(response))) {

		std::cout << "[+] Receiving CRC response from server..." << std::endl;

	}
	else {

		std::cout << SERVER_ERROR_MESSAGE << std::endl;
	}
	
	// Cleanup
	this->clientFileHandler->deleteFile(encryptedFile);

	// Parsing Received CRC from buffer to a number
	this->clientData.serverCksum = this->utils->parseStringBuffer(response.cksum.cksum, CRC_NUM_SIZE);
}

void Client::HandleCRCRequest() {

	CRCValidationPacket request;
	FileCRCResponse response;

	std::cout << "[+] Processing CRC validation request..." << std::endl;

	// Fetching needed data
	std::string filePath = this->clientData.filePath;
	const auto fileCRC = this->clientFileHandler->getFileCRC(filePath);

	// Packing CRC validation request and validate data to avoid buffer overflow
	try {

		this->packCRCRequest(request, filePath);
		this->clientLogger->LogOutput("INFO", classLoggerName, "Packed CRC validation request successfully.", "", "", "");
	}
	catch (const std::exception& e) {

		this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to pack CRC validation request, Error: ", e.what(), "", "");
	}

	// Try to validate file CRC up to 3 times
	for (size_t i = 0; i < CRC_RE_SEND_MAX; i++) {

		Sleep(2);

		if (this->clientData.serverCksum == fileCRC) {

			// For request code 1104
			request.packet_header.requestCode = VALID_CRC_REQUEST_CODE;

			if (this->SendPacket(reinterpret_cast<const uint8_t* const>(&request), sizeof(request))) {

				std::cout << "   - Sending CRC Validation to server." << std::endl;
			}

			std::cout << "   - CRC is valid." << std::endl;

			// For response code 2104
			if (this->ReceivePacket(reinterpret_cast<uint8_t* const>(&response), sizeof(response))) {

				std::cout << "[+] Received ACK from server." << std::endl;
				this->clientLogger->LogOutput("INFO", classLoggerName, "Received ACK from server.", "", "", "");
			}

			break;
		}

		else {

			std::cout << "[+] Re-Sending file packet." << std::endl;

			if (i == 2 && this->clientData.serverCksum != fileCRC) {

				// For request code 1106
				request.packet_header.requestCode = INVALID_CRC_FOURTH_TIME_REQUEST_CODE;

				if (this->SendPacket(reinterpret_cast<const uint8_t* const>(&request), sizeof(request))) {

					std::cout << "[-] CRC is NOT valid for the " << i + 1 << " time, sending abort message to server. " << std::endl;
					this->clientLogger->LogOutput("INFO", classLoggerName, "CRC is NOT valid, cleaning up and disconnecting from server.", "", "", "");
					this->Disconnect();
				}
			}
			else {

				// For request code 1105
				request.packet_header.requestCode = INVALID_CRC_REQUEST_CODE;

				if (this->SendPacket(reinterpret_cast<const uint8_t* const>(&request), sizeof(request))) {

					std::cout << "   - Sending CRC Validation to server..." << std::endl;
				}

				std::cout << "   - CRC is NOT valid, try number " << i + 1 << "." << std::endl;

				// Send request 1103 again
				this->HandleEncryptedFileRequest();
			}
		}
	}
}

std::string Client::encryptFileContent(const std::string& filePath, const size_t fileSize) {

	std::string encryptedContent;
	std::vector<uint8_t> plain;

	// Generating AES private key and update RAM database
	std::cout << "   - Generating AES private key." << std::endl;
	std::string decodedKey = Base64Wrapper::decode(this->clientData.decryptedAESKey.data());
	AESWrapper aes(reinterpret_cast<const unsigned char*>(decodedKey.c_str()), decodedKey.length());

	// Get the file content
	plain.resize(fileSize);
	try {

		plain = this->clientFileHandler->getFileContentInBytes(filePath);

	}
	catch (const std::exception& e) {

		this->clientLogger->LogOutput("ERROR", classLoggerName, "Unable to retreive", filePath.c_str(), "content, Error: ", e.what());
	}

	// Encrypt the file content with the AES private key
	encryptedContent.resize(fileSize);
	encryptedContent = aes.encrypt(reinterpret_cast<const char*>(plain.data()), fileSize);

	plain.clear();
	return encryptedContent;
}

void Client::decryptServerAESKey(const uint8_t* buffer, const size_t size) {

	// Decrypt server AES key and update RAM database
	try {

		std::string decryptedKey = rsaPrivateKey->decrypt(reinterpret_cast<const char*>(buffer), size);
		std::string encodedDecryptedKey = Base64Wrapper::encode(decryptedKey);
		clientData.decryptedAESKey.append(encodedDecryptedKey);
		std::cout << "   - Decrypted server private key successfully." << std::endl;
		this->clientLogger->LogOutput("INFO", classLoggerName, "Server private key", encodedDecryptedKey.data(), "has been decrypted successfully.", "");
	}
	catch (const std::exception& e) {

		std::cerr << "   - Unable to decrypt server private key, Error: " << e.what() << std::endl;
		throw std::exception(e.what());
	}
}

void Client::packRegisterRequest(registerNamePacket& request, unsigned short requestCode, const std::string& username) {

	std::cout << "   - Packing registration request." << std::endl;
	try {

		request.packet_header.requestCode = requestCode;
		request.packet_header.payloadSize = username.length();

		// Validate username length to avoid buffer overflow and update RAM database
		this->utils->validateLengthBeforePacking(username, CLIENT_NAME_SIZE, request.name.name);
		this->clientData.username.append(username.data());
	}
	catch (const std::exception& e) {

		std::cerr << "   - Error packing request." << std::endl;
		throw std::exception(e.what());
	}
}

void Client::packPublicKeyRequest(publicKeyPacket& request, unsigned short requestCode, const std::string& username, const std::string& pubkey) {

	std::cout << "   - Packing public key request." << std::endl;
	try {

		std::vector<uint8_t> bytes = this->utils->hexToBytes(this->clientData.ID.data());
		request.packet_header.requestCode = requestCode;
		request.packet_header.payloadSize = username.length() + pubkey.length();
		memcpy(&request.packet_header.ID.ID, &bytes[0], sizeof(request.packet_header.ID.ID));
		memcpy(&request.name.name, username.data(), username.length());
		bytes.clear();

		// Validate public key length to avoid buffer overflow and encryption/decryption errors, and update RAM database
		if (pubkey.size() == CLIENT_PUBLIC_KEY_SIZE) {

			std::cout << "   - Public key is of valid size." << std::endl;
			memcpy(&request.pubKey, pubkey.data(), sizeof(request.pubKey));
			this->clientData.RSAPublicKey = pubkey;
		}
		else {

			std::cerr << "   - Public key size validation Error." << std::endl;
		}

	}
	catch (const std::exception& e) {

		std::cerr << "   - Error packing request." << std::endl;
		throw std::exception(e.what());
	}
}

void Client::packEncryptedFileRequest(EncryptedFilePacket& request, unsigned short requestCode, const std::string& filePath, const size_t fileSize) {

	std::cout << "   - Packing encrypted file request." << std::endl;
	try {

		std::vector<uint8_t> bytes = this->utils->hexToBytes(this->clientData.ID.data());
		memcpy(&request.packet_header.ID.ID, &bytes[0], sizeof(request.packet_header.ID.ID));
		memcpy(&request.ID.ID, &bytes[0], sizeof(request.ID.ID));
		request.packet_header.requestCode = requestCode;
		request.packet_header.payloadSize = sizeof(request.packet_header.ID.ID) + fileSize + filePath.length();
		request.contentSize = fileSize;
		bytes.clear();

		// Validate filename length to avoid buffer overflow
		this->utils->validateLengthBeforePacking(filePath, FILE_NAME_SIZE, request.fileName.fileName);
		this->clientData.copyFilePath.append(filePath.data());
	}
	catch (const std::exception& e) {

		std::cerr << "   - Error packing request." << std::endl;
		throw std::exception(e.what());
	}
}

void Client::packCRCRequest(CRCValidationPacket& request, const std::string& filePath) {

	std::cout << "   - Packing CRC validation request." << std::endl;
	try {

		std::vector<uint8_t> bytes = this->utils->hexToBytes(this->clientData.ID.data());
		memcpy(&request.packet_header.ID.ID, &bytes[0], sizeof(request.packet_header.ID.ID));
		request.packet_header.payloadSize = sizeof(request.ID.ID) + sizeof(request.fileName.fileName);
		memcpy(&request.ID.ID, &bytes[0], sizeof(request.ID.ID));
		bytes.clear();

		// Validate filename length to avoid buffer overflow
		this->utils->validateLengthBeforePacking(filePath, FILE_NAME_SIZE, request.fileName.fileName);

	}
	catch (const std::exception& e) {

		std::cerr << "   - Error packing request." << std::endl;
		throw std::exception(e.what());
	}
}
