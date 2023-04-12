# EncryptedFileServer
A multithreaded Python server that handles clients requests according to a custom binary TCP based communication protocol. 

### Usage
#### Client:
- Written in C++ and compiled with Visual Studio 2022 on Windows 11, and was checked for memory leaks and warnings.

#### Server:
- Written in Python with PyCharm on Windows 11.

## Project Communication Protocol:
1. Binary TCP based protocol with positive number values represented as little-endian.
2. **Client**:
   - Client socket is implemented with the Winsock library.
   - The A-Symmetric and Symmetric Encryption\Decryption are implemented with the CryptoPP library.
   - Packets are packed and unpacked with and into a custom data structure (structs).
3. **Server**:
   - Server socket is implemented with the Socket library.
   - The A-Symmetric and Symmetric Encryption\Decryption are implemented with the Crypto.Cipher library.
   - Packets are unpacked and packed with the struct library.
4. **Encryption**:
   - A-Symmetric - RSA based encryption with 1024 bits size keys.
   - Symmetric - AES-CBC based, with 128 bits size keys and IV full of zeroes.

5. **Architecture**:

![protocol architecture](https://user-images.githubusercontent.com/119053363/231506449-50fc4e5c-471b-4108-a421-8a48a0b6858b.png)


## Project Architecture and Logic
A Client-Server based architecture.

### Server:
1. The Server will read it's port number from 'port.info' file, if the file does not exists or corrupted a default port number will be assigned.
2. The Server IP Address can be configed from 'config.json' file
3. The Server Will wait for incomming connections in an infinite loop.
4. The Server will interpret the client request according to the received request code according to the following logic:
   - **Registration Request** - If the user already registered, the server will send registration error response, otherwise the server will generate a new UUID and send it back to the client with registration approved response code.
   - **Public key Request** - The Server will receive a public RSA A-Symmetric key from the client, then will generate a private AES key, encrypt it with the received RSA public key and will send it back to the client.
   - **Encrypted File Request** - The Server will receive an encrypted file, decrypt it with pre generated AES private key, calculate the file checksum (CRC) and send the value back to the client.
   - **CRC Validation Request** - The Server will receive a CRC validation success request from the client, otherwise will receive the encrypted file request again up to 3 times.
5. The Server will create and manage a database for the clients and files entries according to the following tables:
#### Clients Table:
| Name | Type | Use |
| --- | --- | --- |
| ID | 16-Bytes | Client unique UUID |
| Name | String | Client name with null termination |
| Public Key | 160-Bytes | Client RSA public key |
| Last Seen | Date and Time | Client last request |

#### Files Table:
| Name | Type | Use |
| --- | --- | --- |
| ID | 16-Bytes | Client unique UUID |
| File Name | String | File name with null termination |
| Path Name | String | File path with null termination |
| Verified | Boolean | For valid CRC |

### Client:
1. The Client will not communicate or be aware to other clients in the system.
2. The Client will have the following files:
   - **transfer.info** - Will have three lines --> 1. connection credentials, 2. Client username, 3. File path to be encrypted and send to the server.
   - **me.info** - Will have three line --> 1. Client username, 2. Client unique UUID received from the server, 3. RSA Private key in Base64 encoding.
3. On any error from the server side, the client will print an error message and will close the connection to the server.
4. **Registration Request** - The Client will read his username from the 'me.info' file, or from the 'transfer.info' file  in case of 'me.info' file is corrupted. the received UUID will then be appended to the 'me.info' file.
5. **Public Key Request** - The Client will generate A-Symmetric key pair, will send the public key to the server, and then append the private key to the 'transfer.info' file after encoding it in Base64. Additionally the client will receive the server's encrypted AES private key and decrypt it with it's RSA private key.
6. **Encrypted File Request** - The Client will calculate the CRC of the file path from the 'transfer.info' file, will create an encrypted copy of it and then send it to the server.
7. **CRC Validation Request** - The Client will receive the decrypted file CRC from the server, if the CRC is invalid the client will send the encrypted file request up to 3 times.


### Protocol Packet Format:
#### Requests:
**Header:**
| Request | Field | Size | Use |
| --- | --- | --- | --- |
| Header | Client ID | 16-Bytes | Client unique UUID |
| Header | Version | 1-Byte | Client version |
| Header | Request code | 2-Bytes | Client request code |
| Header | Payload size | 4-Bytes | Packet payload size |
| Payload | Payload | Changing | Payload size |

**Payload:**\
Request Code 1100 - Registration.
| Field | Size | Use |
| --- | --- | --- |
| Name | 255-Bytes | Client name with null termination |


Request Code 1101 - Public Key.
| Field | Size | Use |
| --- | --- | --- |
| Name | 255-Bytes | Client name with null termination |
| Public key | 160-Bytes | Client Public key |


Request Code 1103 - Encrypted File.
| Field | Size | Use |
| --- | --- | --- |
| Client ID | 16-Bytes | Client unique UUID |
| Content size | 4-Bytes | File content size after encryption |
| File name | 255-Bytes | Sent file name |
| File content | Changing | Encrypted file content |

Request Code 1104 - Valid CRC.\
Request Code 1105 - Invalid CRC, will send request 1103 again.\
Request Code 1106 - Invalid CRC for the 3rd time.
| Field | Size | Use |
| --- | --- | --- |
| Client ID | 16-Bytes | Client unique UUID |
| File name | 255-Bytes | Sent file name |


#### Responses:
**Header:**
| Response | Field | Size | Use |
| --- | --- | --- | --- |
| Header | Version | 1-Byte | Server version |
| Header | Response code | 2-Bytes | Server response code |
| Header | Payload size | 4-Bytes | Packet payload size |
| Payload | Payload | Changing | Payload size |

**Payload:**\
Response Code 2100 - Registration approved.
| Field | Size | Use |
| --- | --- | --- |
| Client ID | 16-Bytes | Client unique UUID |

Response Code 2101 - Registration Error.

Response Code 2102 - A-Symmetric Keys exchange.
| Field | Size | Use |
| --- | --- | --- |
| Client ID | 16-Bytes | Client unique UUID |
| AES encrypted key | 128-Bytes | Server encrypted AES key |

Response Code 2103 - Encrypted file with CRC.
| Field | Size | Use |
| --- | --- | --- |
| Client ID | 16-Bytes | Client unique UUID |
| Content size | 4-Bytes | File content size after encryption |
| File name | 255-Bytes | Received file name |
| Cksum | 4-Bytes | CRC after decryption |

Response Code 2104 - ACK message.
