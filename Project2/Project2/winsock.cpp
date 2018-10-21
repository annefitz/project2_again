
#include "winsock.h"


SOCKET Winsock::OpenSocket (void)
{
	// open a UDP socket
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);  //SOCK_DGRAM for UDP sockets
	if(sock == INVALID_SOCKET)
	{
		printf ("socket() generated error %d\n", WSAGetLastError ());
		WSACleanup ();	
		exit (-1);	// not graceful, but sufficient for our purposes
	}

	struct sockaddr_in bind_addr;

	// bind to the local address and port 0
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_addr.S_un.S_addr = htonl(INADDR_ANY); // INADDR_ANY: choose the local address of this computer
	bind_addr.sin_port = htons (0);	// 0: let OS select the next available port on which
									// the UDP sock listens for incoming response						

	if (bind (sock, (struct sockaddr*) &bind_addr, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
	{
		printf ("Bind failed with %d\n", WSAGetLastError());
		exit (-1);
	}

	// then sendto and recvfrom
	return sock;
}
