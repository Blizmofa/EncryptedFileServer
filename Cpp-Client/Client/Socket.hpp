/*
* Socket custom namespace for WinSock socket requirements and utils.
*/

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "ws2_32.lib")

#include <WinSock2.h>
#include <Windows.h>

#pragma once

namespace Socket {

	/* Initializes WinSock */
	bool init();

	/* WSACleanup */
	void cleanup();

	/* Return WSA last error */
	int getLastError();

	/* Closing down socket */
	bool closeSocket(SOCKET sock);
}



