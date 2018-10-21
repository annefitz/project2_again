/*	main.cpp
	CPS 472 Sample Code

	To compile, you need to add additional libraries: 
	1. Right Click on project name, select "Properties"
	2. Go to Linker/Input/Additional Dependencies: ws2_32.lib;winmm.lib;Iphlpapi.lib;Psapi.lib;
	   use ; to separate them.
*/

#define _WINSOCK_DEPRECATED_NO_WARNINGS  // needed for "inet_add()" function call

#include "winsock.h"  // must include winsock2.h at the very top of the file before include others
#include "headers.h"
#include "cpu.h"
#include "dns.h"
#include "lookup.h"

#include <iostream>



// this class is passed to all threads, acts as shared memory
class Parameters{
public:
	HANDLE mutex;
	HANDLE finished;
	HANDLE eventQuit;
};

// this function is where the thread starts
UINT make_thread(LPVOID pParam)
{
	Parameters *p = ((Parameters*)pParam);

	// wait for mutex, then print and sleep inside the critical section
	WaitForSingleObject(p->mutex, INFINITE);					// lock mutex
	printf ("Thread %d started\n", GetCurrentThreadId ());		// always print inside critical section to avoid screen garbage
	Sleep (1000);
	ReleaseMutex(p->mutex);										// release critical section

	// signal that this thread has exitted
	ReleaseSemaphore(p->finished, 1, NULL);

	return 0;
}

int ref_main(int argc, char* argv[])
{
	if (argc != 2) {
		std::printf("Invalid number of args");
		return -1;
	}
	int arg_type;
	string host = argv[1];
	if (isdigit(host[0])) {
		std::printf("IP\n");
		arg_type = 1;
		if (inet_addr(argv[1]) == INADDR_NONE) {
			std::printf("Invalid IP");
			return -1;
		}
		host = host + ".in-addr.arpa";
	}
	else {
		std::printf("HOSTNAME\n");
		arg_type = 2;
	}
	cout << "argc: " << argc << ", argv: " << host << endl;
	WSADATA wsaData;

	getchar();

	// Initialize WinSock in your project only once!
	WORD wVersionRequested = MAKEWORD(2,2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError ());
		WSACleanup();	
		return -1;
	}


	printf ("-----------------\n");

	// print our primary/secondary DNS IPs
	DNS mydns;
	string dnsIP = ""; 
	mydns.printDNSServer (dnsIP);	

	printf ("-----------------\n");

	CPU cpu;
	// average CPU utilization over 500 ms; must sleep *after* the constructor of class CPU and between calls to GetCpuUtilization
	Sleep (500);
	// now print
	double util = cpu.GetCpuUtilization (NULL);
	printf ("current CPU utilization %f%%\n", util);

	printf ("-----------------\n");

	// thread handles are stored here; they can be used to check status of threads, or kill them
	HANDLE *ptrs = new HANDLE [2];
	Parameters p;
	
	// create a mutex for accessing critical sections (including printf)
	p.mutex = CreateMutex (NULL, 0, NULL);
	
	// create a semaphore that counts the number of active threads
	p.finished = CreateSemaphore(NULL, 0, 2, NULL);
	p.eventQuit = CreateEvent (NULL, true, false, NULL);

	// get current time
	DWORD t = timeGetTime();

	// structure p is the shared space between the threads
	ptrs[0] = CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)make_thread, &p, 0, NULL);
	ptrs[1] = CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)make_thread, &p, 0, NULL);

	// make sure this thread hangs here until the other two quit; otherwise, the program will terminate prematurely
	WaitForSingleObject(p.finished, INFINITE);
	WaitForSingleObject(p.finished, INFINITE);

	// ----------------------------  testing the DNS query --------

//	string host = "www.yahoo.com" ; 
//	string host = "7.74.238.131.in-addr.arpa"; 
	int pkt_size = sizeof(FixedDNSheader) + sizeof(QueryHeader) + host.size() + 2; //+1 byte for "size" for last substring, +1 for "0" meaning the end of question
	
	char* pkt = new char [pkt_size];

	FixedDNSheader * dHDR = (FixedDNSheader *) pkt; 
	QueryHeader *qHDR = (QueryHeader*) ( pkt+ pkt_size -sizeof (QueryHeader) );

	dHDR->ID = htons(102); 
	dHDR->questions = htons(1); 
	dHDR->addRRs = 0;
	dHDR->answers = 0;
	dHDR->authRRs = 0;
	dHDR->flags = htons( DNS_QUERY | DNS_RD | DNS_STDQUERY );
//	dHDR->flags = htons( 0x0100 );  

	int position = host.find ("."); 
	string sub_str; 

	int i = 0, sub_size = 0, hdr_size = sizeof(FixedDNSheader); 

	host +="." ; 
	while ( position != -1 )
	{
		sub_size = position - i; 
		sub_str  = host.substr( i, position );

		pkt[hdr_size + i] = sub_size;  // specify the size of the chunk (subdomain)
		i++; 
		memcpy ( pkt + hdr_size + i, sub_str.c_str(), sub_size ); // specify the actual subdomain

		i += sub_size; 
		position = host.find (".", i ); 
	}	
	pkt[hdr_size+i]= 0; 

	qHDR->qclass = htons(DNS_INET); 
//	qHDR->qclass = htons( 0x0001); 

	// if hostname
	if (arg_type == 2) {
		qHDR->type = htons(DNS_A);
	}
	// if IP
	else if (arg_type == 1) {
		qHDR->type = htons(DNS_PTR);  // for reverse dns lookup
	}

	Winsock ws;

	SOCKET sock = ws.OpenSocket(); // defined in winsock.h

	// set up the address of where we're sending data
	struct sockaddr_in send_addr ;
	send_addr.sin_family = AF_INET;
	send_addr.sin_addr.S_un.S_addr = inet_addr( dnsIP.c_str() ); // 208.67.222.222
	send_addr.sin_port = htons ( 53 );

	int send_addrSize=  sizeof(struct sockaddr_in); 

	int sentbytes = sendto (sock, pkt,  pkt_size, 0, (struct sockaddr*) &send_addr,  send_addrSize );
	cout<<"sentbytes=" << sentbytes <<endl; 

	for ( int i = 0; i< pkt_size; i++)
	{
		cout << "i= " << i << " " << pkt[i] << endl;
	}
	cout << endl; 

	char recv_buf [512]; 

	int recvbytes = 0; 
	if (sentbytes > 0)	
		recvbytes = recvfrom (sock, recv_buf, 512, 0,  (sockaddr *)&send_addr, &send_addrSize);

	cout<< "recv_bytes=" << recvbytes <<endl; 

	FixedDNSheader * rDNS = (FixedDNSheader *) recv_buf; 
	cout << "ID=" << ntohs( dHDR->ID )<< "??" << ntohs( rDNS->ID )<<endl; 
	cout << "questions=" << ntohs( rDNS->questions ) <<endl; 
	cout << "Answers=" << ntohs( rDNS->answers )<<endl; 
	cout << "authRRs="<<ntohs( rDNS->authRRs) <<endl; 
	cout << "addRRs=" << ntohs( rDNS->addRRs )<<endl; 

	printf ( "flag 0x=%x\n", ntohs( rDNS->flags ) ) ; 
	unsigned short rcode = 0x0F; 
	rcode = rcode & ntohs( rDNS->flags ); 
	rcode = rcode & ntohs( rDNS->flags ); 
	cout<<"Rcode= " << rcode <<endl; ; 

	// for debugging:
//	for ( int i = 0; i< recvbytes; i++)
//	{
//		printf("%x\t", i, recv_buf[i] ); 
//	}
//	cout<<endl; 


	closesocket(sock); 

	delete[] pkt; 

	
	printf ("Terminating main(), completion time %d ms\n", timeGetTime() - t);

	getchar();

	WSACleanup();	

	return 0; 
}

