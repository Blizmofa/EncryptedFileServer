/*
* Client Class to handle client side project protocol.
*/

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <string>
#include <iostream>
#include <vector>
#include "Socket.hpp"
#include "Logger.hpp"
#include "FileHandler.hpp"
#include "ClientUtils.hpp"
#include "ProtocolHandler.hpp"
#include "RSAWrapper.hpp"
#include "Base64Wrapper.hpp"
#include "AESWrapper.hpp"


class Client {

private:
	const std::string classLoggerName = "Client";
	SOCKET clientSocket;
	SOCKADDR_IN serverInfo;
	Logger* clientLogger;
	ClientUtils* utils;
	FileHandler* clientFileHandler;
	RSAPrivateWrapper* rsaPrivateKey;
	
public:

	/* RAM struct for easy access to needed data */
	struct ClientData {

		std::string ID;
		std::string username;
		std::string RSAPublicKey;
		std::string RSAPrivateKey;
		std::string decryptedAESKey;
		std::string filePath;
		std::string copyFilePath;
		unsigned long long serverCksum{ DEFAULT_INITIALIZE_VALUE };

	} clientData;


public:

	/* Class Constructor and Destructor */
	Client();
	~Client();

	/* Connect to server according to a given IP Address and Port number */
	bool Connect(const std::string &ip_address, const size_t port);

	/* Disconnect from server and closes client socket */
	void Disconnect();

	/* Shutdown the connection, client can still receive but can't send */
	bool Shutdown();

	/* Returns WSA last error */
	int GetLastError() const { return Socket::getLastError(); } 

	/* Returns the client username */
	std::string GetClientUsername(const std::string &mainFileName, const std::string &backupFileName) const;

	/* Main send method, sending packed packet to server */
	bool SendPacket(const uint8_t* const buffer, const size_t size) const;

	/* Auxiliary method to send file content up to 4GB */
	bool sendFileContent(const std::string& filePath, const size_t size) const;

	/* Main receive method, receives packed packet from server */
	bool ReceivePacket(uint8_t* const buffer, const size_t size) const;

	/* Creates needed client files according to requirements */
	void CreateClientFiles(const std::string& connectionDetails, const std::string& clientName, const std::string& filePath);

	/* Sends and receives registration to and from server, unpacking and store data accordinglly */
	void HandleRegisterRequest();

	/* Sends and receives public/private key request to and from server, unpacking and store data accordinglly */
	void HandlePubKeyRequest();

	/* Sends and receives encrypted file request key to and from server, unpacking and store data accordinglly */
	void HandleEncryptedFileRequest();
	
	/* Sends file content back to server up to three times if needed */
	void HandleCRCRequest();

private:

	/* Auxiliary method to encrypt a given file content */
	std::string encryptFileContent(const std::string& filePath, const size_t fileSize);

	/* Auxiliary method to decrypte the received server AES session key */
	void decryptServerAESKey(const uint8_t* buffer, const size_t size);

	/* Auxiliary method to pack registration request */
	void packRegisterRequest(registerNamePacket& request, unsigned short requestCode, const std::string& username);

	/* Auxiliary method to pack public key request */
	void packPublicKeyRequest(publicKeyPacket& request, unsigned short requestCode, const std::string& username, const std::string& pubkey);

	/* Auxiliary method to pack encrypted file request */
	void packEncryptedFileRequest(EncryptedFilePacket& request, unsigned short requestCode, const std::string& filePath, const size_t fileSize);

	/* Auxiliary method to pack CRC validation request */
	void packCRCRequest(CRCValidationPacket& request, const std::string& filePath);
};

