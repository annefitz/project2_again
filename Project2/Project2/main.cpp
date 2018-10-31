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

string getName(u_char *parser, u_char *buf, int *idx);
string dnsResponseConvert(string name);
void PrintResponse(string name, string rdata);

// this class is passed to all threads, acts as shared memory
class Parameters {
public:
	HANDLE mutex;
	HANDLE finished;
	HANDLE eventQuit;
};

// this function is where the thread starts
UINT thread(LPVOID pParam)
{
	Parameters *p = ((Parameters*)pParam);

	// wait for mutex, then print and sleep inside the critical section
	WaitForSingleObject(p->mutex, INFINITE);					// lock mutex
	printf("Thread %d started\n", GetCurrentThreadId());		// always print inside critical section to avoid screen garbage
	Sleep(1000);
	ReleaseMutex(p->mutex);										// release critical section

	// signal that this thread has exitted
	ReleaseSemaphore(p->finished, 1, NULL);

	return 0;
}

int main(int argc, char* argv[])
{
	if (argc != 2) {
		std::printf("Invalid number of args.\n");
		getchar();
		return -1;
	}
	int arg_type;
	int num_threads;
	string backwardsIP;
	string host = argv[1];
	if (host.find(".") != string::npos) {
		if (isdigit(host[0])) {
			std::printf("IP\n");
			arg_type = 1;
			if (inet_addr(argv[1]) == INADDR_NONE) {
				std::printf("Invalid IP");
				getchar();
				return -1;
			}
			int position = host.find(".");
			int i = 0; int size = 0;
			while (position != string::npos) {
				size = position - i;
				backwardsIP.insert(0, host.substr(i, size));
				backwardsIP.insert(0, ".");
				i += size + 1;
				position = host.find(".", i);
			}
			backwardsIP.insert(0, host.substr(i, host.length() - i));
			cout << "FORWARD IP: " << host << " BACKWARDS IP: " << backwardsIP << endl;
			host = backwardsIP + ".in-addr.arpa";
		}
		else {
			std::printf("HOSTNAME\n");
			arg_type = 2;
		}
		cout << "argc: " << argc << ", argv: " << host << endl;
	}
	/*else {
		cout << "BATCH LOOKUP, num threads: " << host << endl;
		string filename = "dns-in.txt";
		num_threads = stoi(argv[1]);
		ifstream fin;
		fin.open(filename);
		if (fin.fail()) {
			cout << "File failed to open.\n";
			return -1;
		}
		else {
			cout << "Opened " << filename << endl;
		}
		string url = "";
		string port = "";
		queue<string> inQ;
		while (!fin.eof()) {
			fin >> port;
			//cout << port << endl;
			fin >> url;
			//cout << url << endl;
			inQ.push(url);
		}
		cout << "Size of queue: " << inQ.size() << endl;
		getchar();
		
		return -1;
	}*/

	WSADATA wsaData;

	// Initialize WinSock in your project only once!
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		getchar();
		return -1;
	}

	printf("-----------------\n");

	// print our primary/secondary DNS IPs
	DNS mydns;
	string dnsIP = "";
	mydns.printDNSServer(dnsIP);

	// set up the address of where we're sending data
	struct sockaddr_in send_addr;
	send_addr.sin_family = AF_INET;
	send_addr.sin_addr.S_un.S_addr = inet_addr(dnsIP.c_str()); // 208.67.222.222
	send_addr.sin_port = htons(53);

	printf("-----------------\n");

	CPU cpu;
	// average CPU utilization over 500 ms; must sleep *after* the constructor of class CPU and between calls to GetCpuUtilization
	Sleep(500);
	// now print
	double util = cpu.GetCpuUtilization(NULL);
	printf("current CPU utilization %f%%\n", util);

	printf("-----------------\n");

	// thread handles are stored here; they can be used to check status of threads, or kill them
	HANDLE *ptrs = new HANDLE[2];
	Parameters p;

	// create a mutex for accessing critical sections (including printf)
	p.mutex = CreateMutex(NULL, 0, NULL);

	// create a semaphore that counts the number of active threads
	p.finished = CreateSemaphore(NULL, 0, 2, NULL);
	p.eventQuit = CreateEvent(NULL, true, false, NULL);

	// get current time
	DWORD t = timeGetTime();

	// structure p is the shared space between the threads
	ptrs[0] = CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)thread, &p, 0, NULL);
	ptrs[1] = CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)thread, &p, 0, NULL);

	// make sure this thread hangs here until the other two quit; otherwise, the program will terminate prematurely
	WaitForSingleObject(p.finished, INFINITE);
	WaitForSingleObject(p.finished, INFINITE);

	// -------------------------------  testing the DNS query  --------------------------------------------

	Question q;

	//+1 byte for "size" for last substring, +1 for "0" meaning the end of question
	size_t pkt_size = sizeof(FixedDNSheader) + host.size() + 2 + sizeof(QueryHeader);
	char *pkt = new char[pkt_size];

	//q.MakePacket(pkt, dHDR, qHDR);
	q.CreatePacket(host, arg_type, pkt, pkt_size);

	Winsock ws;

	SOCKET sock = ws.OpenSocket(); // defined in winsock.h

	int send_addrSize = sizeof(struct sockaddr_in);

	int sentbytes = sendto(sock, pkt, pkt_size, 0, (struct sockaddr*) &send_addr, send_addrSize);
	cout << "sentbytes=" << sentbytes << endl;

//	for (int i = 0; i < pkt_size; i++)
//	{
//		cout << "i= " << i << " " << pkt[i] << endl;
//	}

	cout << endl;

	char recv_buf[512];
	//set timeout for receive
	timeval* timeout = new timeval;
	//set timeout for 10s
	timeout->tv_sec = 10;
	timeout->tv_usec = 0;
	fd_set Sockets;
	Sockets.fd_count = 1;
	Sockets.fd_array[0] = sock;

	int recvbytes = 0;
	if (sentbytes > 0) {

		recvbytes = recvfrom(sock, recv_buf, 512, 0, (struct sockaddr *) &send_addr, &send_addrSize);

		if (select(0, NULL, &Sockets, NULL, timeout) > 0) {
			cout << "No timeout!" << endl;
			getchar();
		}
		else {
			cout << "TIMEOUT" << endl;
			getchar();
		}
	}

	u_char *reader = (u_char*)
		&recv_buf[pkt_size];

	cout << "recv_bytes=" << recvbytes << endl;
//	for (int i = 0; i < recvbytes; i++)
//	{
//		cout << "recv= " << i << " " << recv_buf[i] << endl;
//	}

	FixedDNSheader * rDNS = (FixedDNSheader *)recv_buf;
	FixedRR ansRR;

	unsigned short rcode = 0x0F;
	rcode = rcode & ntohs(rDNS->flags);
	if (rcode == 3) {
		cout << "No DNS entry" << endl;
		getchar();
		return -1;
	}
	else if (rcode == 2) {
		cout << "Authoritative DNS server not found" << endl;
		getchar();
		return -1;
	}
	else if (rcode > 0) {
		cout << "Error type: " << rcode << endl;
		getchar();
		return -1;
	}

	int end_idx = 0;

	string name = getName(reader, (u_char*)recv_buf, &end_idx);
	string rdata;
	
	// for debugging:
	for (int i = 0; i < recvbytes; i++)
	{
		//printf("%d : %c\n", i, reader[i]);
		//cout << "i: " << i << " recv: " << recv_buf[i] << endl;
	}
	cout << endl;

	reader = reader + end_idx;
	
	FixedRR *fixedrr = (FixedRR *)reader;
	reader = reader + sizeof(FixedRR);

	if (ntohs(fixedrr->type) == 1) // IP address
	{
		int i;
		for (i = 0; i < ntohs(fixedrr->len); i++)
		{
			rdata.append(to_string((int)reader[i]));
			rdata.push_back('.');
		}

		rdata.pop_back(); // remove the last period
	}
	else
	{
		rdata = getName(reader, (u_char*) recv_buf, &end_idx);
	}

	PrintResponse(name, rdata);

	closesocket(sock);

	delete[] pkt;

	printf("Terminating main(), completion time %d ms\n", timeGetTime() - t);

	getchar();

	WSACleanup();

	return 0;
}

string getName(u_char *parser, u_char *buf, int *idx)
{
	string name;
	bool compressed = false;
	int offset, i, j, num_bytes;
	int arr_ptr = 0;

	*idx = 1;
	int count = 0;

	// read the names in 3www6google3com format
	while (*parser != 0)
	{
		//cout << "\n GETNAME IDX: " << *idx << endl;
		if (*parser >= 192)
		{
			compressed = true;
			offset = (*parser) * 256 + *(parser + 1) - 49152; // 49152 = 11000000 00000000
			parser = buf + offset - 1;
		}
		else
		{
			name.push_back(*parser);
		}

		parser = parser + 1;

		if (!compressed)
			*idx = *idx + 1; // if it isn't compressed (hasn't jumped) then we count up
	}

	if (compressed)
	{
		*idx = *idx + 1; // number of steps we actually moved forward in the packet
	}

	name = dnsResponseConvert(name);

	return name;
}

// convert from <size><string><size><string>... (3www6google3com)
string dnsResponseConvert(string name) {

	string host(name);
	char seg_size;

	name.clear();
	for (int i = 0; i < static_cast<int>(host.length()); i++)
	{
		seg_size = host[i];

		for (int j = 0; j < (int)seg_size; j++) {
			name.push_back(host[++i]);
		}

		if (i < static_cast<int>(host.length()) - 1)
			name.push_back('.');

	}

	return name;
}

void PrintResponse(string name, string rdata)
{
	cout << "Answer RR: " << endl;
	cout << "name: " << name << endl;
	cout << "rdata: " << rdata.c_str() << endl;
}
