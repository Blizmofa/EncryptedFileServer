/*
* Socket namespace implementation.
*/

#include "Socket.hpp"

namespace Socket {
	
	bool init() {
		
		WSAData wsaData;
		return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
	}

	void cleanup() {
		
		WSACleanup();
	}

	int getLastError() {

		return WSAGetLastError();
	}

	bool closeSocket(SOCKET sock) {

		return closesocket(sock) == 0;
	}
}




