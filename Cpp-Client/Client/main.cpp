/*
* Project main file.
*/

#include "Client.hpp"
#include "ClientUtils.hpp"
#include "FileHandler.hpp"

int main(const int argc, const char* argv[]) {

	// Initializations
	std::string ip {NULL};
	size_t port {0};
	Client* client = new Client();
	ClientUtils* utils = new ClientUtils();
	FileHandler* fileHandler = new FileHandler();

	// Test Files
	std::string file_path = "1KB.txt"; 
	std::string file_path1 = "1MB.docx"; 
	std::string file_path2 = "13MB.docx"; 
	std::string file_path3 = "32MB.docx"; 
	std::string file_path4 = "1MB.ppt"; 

	// Create Client needed files
	client->CreateClientFiles("127.0.0.1:8080", "James Brice", file_path);

	// Retrieving connection details from file
	std::vector<std::string> lines = fileHandler->getFileContent(SERVER_INFO);
	ip = utils->getIP(lines);
	port = utils->getPort(lines);

	// Validate ip and port
	if (!utils->validateConnectionCredentials(port, ip)) {
		std::cout << "[!] Invalid connection credentials, shutting down." << std::endl;
		std::exit(EXIT_FAILURE);
	}

	// Connect to server
	if (client->Connect(ip, port)) {

		// Sending registeration request to server and hanlde response
		client->HandleRegisterRequest();

		// Generate RSA key pair, send public key to server and handle response
		client->HandlePubKeyRequest();

		// Send file request to server and handle response
		client->HandleEncryptedFileRequest();

		// Send CRC Validation packet to server and handle response
		client->HandleCRCRequest();
	
	} 
	else {

		std::cout << SERVER_ERROR_MESSAGE << std::endl;
	}

	// Cleanup client resources
	lines.clear();
	client->clientData = {};
	client->Disconnect();

	// debug check for memory leaks
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

	return 0;

}
