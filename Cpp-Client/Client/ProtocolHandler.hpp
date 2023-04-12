/*
* ProtocolHandler file for protocol structs and constants.
*/

#pragma once

#include <vector>

// Constants
const size_t CLIENT_ID_SIZE = 16;
const size_t CRC_NUM_SIZE = 10;
const size_t CLIENT_NAME_SIZE = 255;
const size_t CLIENT_PUBLIC_KEY_SIZE = 160;
const size_t SERVER_RSA_KEY_SIZE = 128;
const size_t FILE_NAME_SIZE = 255;
const size_t PACKET_MAX_BUFFER = 1024;
const size_t CLIENT_VERSION = 3;
const size_t PORT_LOWER_BOUND = 1;
const size_t PORT_UPPER_BOUND = 65535;
const size_t IP_LOWER_BOUND = 0;
const size_t IP_UPPER_BOUND = 255;
const size_t IP_DEFAULT_NUM_OF_COMPONENTS = 4;
const size_t ME_FILE_MAX_NUMBER_OF_LINES = 3;
const size_t CLIENT_USERNAME_FILE_INDEX = 0;
const size_t CLIENT_UUID_FILE_INDEX = 1;
const size_t CLIENT_ENCODED_KEY_FILE_INDEX = 2;
const size_t CLIENT_FILE_PATH_FILE_INDEX = 2;
const size_t DEFAULT_INITIALIZE_VALUE = 0;
const size_t CRC_RE_SEND_MAX = 3;
const uint8_t NULL_TERMINATOR = '\0';
const std::string SERVER_ERROR_MESSAGE = "[!] Server responded with an error.";
const std::string ME_INFO = "me.info";
const std::string SERVER_INFO = "transfer.info";

// Request Codes
const size_t REGISTRATION_REQUEST_CODE = 1100;
const size_t PUBKEY_REQUEST_CODE = 1101;
const size_t FILE_REQUEST_CODE = 1103;
const size_t VALID_CRC_REQUEST_CODE = 1104;
const size_t INVALID_CRC_REQUEST_CODE = 1105;
const size_t INVALID_CRC_FOURTH_TIME_REQUEST_CODE = 1106;

// Response Codes
const size_t REGISTRATION_APPROVED_RESPONSE_CODE = 2100;
const size_t REGISTRATION_FAILED_RESPONSE_CODE = 2101;
const size_t ENCRYPTED_AES_KEY_RESPONSE_CODE = 2102;
const size_t FILE_WITH_CRC_RESPONSE_CODE = 2103;
const size_t SERVER_ACK_RESPONSE_CODE = 2104;

#pragma pack(push, 1)

/*
* Client Request Structs
*/
struct ClientID {

	uint8_t ID[CLIENT_ID_SIZE];
	ClientID() : ID { DEFAULT_INITIALIZE_VALUE } {}
};

struct ClientName {

	uint8_t name[CLIENT_NAME_SIZE];
	ClientName() : name{ NULL_TERMINATOR } {}
};

struct PublicKey {

	unsigned char publicKey[CLIENT_PUBLIC_KEY_SIZE];
	PublicKey() : publicKey{ DEFAULT_INITIALIZE_VALUE } {}
};

struct FileName {

	unsigned char fileName[FILE_NAME_SIZE];
	FileName() : fileName{ NULL_TERMINATOR } {}
};

struct FileCRC {

	uint8_t cksum[CRC_NUM_SIZE];
	FileCRC() : cksum{ NULL_TERMINATOR } {}
};

// General Request Header Format
struct serverRequestPacket 
{
	ClientID ID;
	const uint8_t version = { CLIENT_VERSION };
	unsigned short requestCode = { DEFAULT_INITIALIZE_VALUE };
	unsigned int payloadSize = { DEFAULT_INITIALIZE_VALUE };
};

// For request code 1100
struct registerNamePacket {

	serverRequestPacket packet_header;
	ClientName name;
};

// For request code 1101
struct publicKeyPacket {

	serverRequestPacket packet_header;
	ClientName name;
	PublicKey pubKey;
};

// For request code 1103
struct EncryptedFilePacket {

	serverRequestPacket packet_header;
	ClientID ID;
	unsigned int contentSize = { DEFAULT_INITIALIZE_VALUE };
	FileName fileName;
};

// For request codes 1104/1105/1106
struct CRCValidationPacket {

	serverRequestPacket packet_header;
	ClientID ID;
	FileName fileName;
};

/*
* Server Response Structs
*/

// General Response Header Format
struct serverResponsePacket {

	unsigned short version = { DEFAULT_INITIALIZE_VALUE };
	unsigned short responseCode = { DEFAULT_INITIALIZE_VALUE };
	unsigned int payloadSize = { DEFAULT_INITIALIZE_VALUE };
};

// For response 2100
struct clientIDResponsePayload {

	serverResponsePacket packet_header;
	ClientID ID;
};

// For response 2102
struct clientEncryptedKeyResponsePayload {

	serverResponsePacket packet_header;
	struct {
		ClientID ID;
		uint8_t serverEncryptedKey[SERVER_RSA_KEY_SIZE];
	} payload;
};

// For response 2103
struct FileCRCResponse {

	serverResponsePacket packet_header;
	ClientID ID;
	unsigned int contentSize = { DEFAULT_INITIALIZE_VALUE };
	FileName fileName;
	FileCRC cksum;
};

#pragma pack(pop)


