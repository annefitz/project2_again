/*	main.cpp
	CPS 472 Sample Code

	To compile, you need to add additional libraries:
	1. Right Click on project name, select "Properties"
	2. Go to Linker/Input/Additional Dependencies: ws2_32.lib;winmm.lib;Iphlpapi.lib;Psapi.lib;
	   use ; to separate them.
*/

#define _WINSOCK_DEPRECATED_NO_WARNINGS  // needed for "inet_add()" function call
#define TIMEOUTUS 5000000

#include "winsock.h"  // must include winsock2.h at the very top of the file before include others
#include "headers.h"
#include "cpu.h"
#include "dns.h"
#include "lookup.h"

#include <iostream>

// this class is passed to all threads, acts as shared memory
class Parameters {
public:
	_RTL_CRITICAL_SECTION mutex;
	_RTL_CRITICAL_SECTION count_mutex;
	HANDLE finished;
	HANDLE eventQuit;
	queue<string> inq;
	int mode, num_tasks;

	double numSuccessful;
	double numNoDNS;
	double numNoAuth;
	double numTimeout;
	double numRetxAttempts; // ^ same but with resending attempts
	double totalDelay;

	Parameters() {
		InitializeCriticalSection(&mutex);
		InitializeCriticalSection(&count_mutex);
	}
};

string getName(u_char *parser, u_char *buf, int *idx);
Parameters* resolveDNSbyName(string host, int arg_type, Parameters *p);
string dnsResponseConvert(string name);
void PrintResponse(string name, string rdata, FixedDNSheader *rDNS, FixedRR *fixedrr);
string makeBackwardsIP(string arg);

// this function is where the thread starts
UINT thread(LPVOID pParam)
{
	Parameters *p = ((Parameters*)pParam);
	DWORD start;
	string host;

	while (true) {

		// wait for mutex, then print and sleep inside the critical section
		EnterCriticalSection(&(p->mutex));  // lock mutex

			if (p->num_tasks <= 0 || p->inq.empty()) {
				LeaveCriticalSection(&(p->mutex));
				break;
			}
			
			host = p->inq.front();
			p->inq.pop();
			p->num_tasks--;
			cout << "Thread " << GetCurrentThreadId() << ": num_tasks_left = " << p->num_tasks << endl;
			//cout << "Q SIZE: " << p->inq.size() << endl;
		LeaveCriticalSection(&(p->mutex));

		if (p->mode == 2)
			host = makeBackwardsIP(host);

		if (host == "" || host == "\0")
			continue; // invalid IP

		start = timeGetTime();
		p = resolveDNSbyName(host, 1, p);

		EnterCriticalSection(&(p->count_mutex));
			p->totalDelay += (timeGetTime() - start);
		LeaveCriticalSection(&(p->count_mutex));
	}
	Sleep(1000);

	cout << "Thread " << GetCurrentThreadId() << "done.\n";

	// signal that this thread is exiting
	EnterCriticalSection(&(p->mutex));
		Sleep(10); // helps the main loop keep up with the threads exiting
		ReleaseSemaphore(p->finished, 1, NULL); // signal that the thread is finished
	LeaveCriticalSection(&(p->mutex));

	return 0;
}


int main(int argc, char* argv[])
{
	if (argc != 2) {
		std::printf("Invalid number of args.\n");
		getchar();
		return -1;
	}
	DWORD t;
	int arg_type, num_threads, total_tasks;
	string host = argv[1];
	Parameters p;
	queue<string> inQ;

	WSADATA wsaData;

	// Initialize WinSock in your project only once!
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		getchar();
		return -1;
	}

	// INTERACTIVE MODE --------------------------------------------------
	if (host.find(".") != string::npos) {

		cout << "Starting interactive mode\n";
		p.mode = 1;

		if (isdigit(host[0])) {
			arg_type = 1;
			host = makeBackwardsIP(argv[1]);
		}
		else {
			arg_type = 2;
		}

		cout << "HOST: " << host << endl;

		inQ.push(host);

		// thread handles are stored here; they can be used to check status of threads, or kill them
		HANDLE *ptrs = new HANDLE[2];

		// create a semaphore that counts the number of active threads
		p.finished = CreateSemaphore(NULL, 0, 2, NULL);
		p.eventQuit = CreateEvent(NULL, true, false, NULL);
		p.num_tasks = size(inQ);
		p.inq = inQ;

		// get current time
		t = timeGetTime();

		HANDLE t1 = CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)thread, &p, 0, NULL);

		WaitForSingleObject(p.finished, INFINITE);

	}

	// BATCH MODE --------------------------------------------------------
	else {
		string filename = "dns-in.txt";
		num_threads = stoi(argv[1]);

		// open batch input file
		ifstream fin;
		fin.open(filename);
		if (fin.fail()) {
			cout << "File failed to open.\n";
			return -1;
		}
		else {
			cout << "Opened " << filename << endl;
		}

		std::ofstream out("out.txt");
		std::streambuf *coutbuf = std::cout.rdbuf(); //save old buf
		std::cout.rdbuf(out.rdbuf()); //redirect std::cout to out.txt!

		// read each IP into a queue
		string url = "";
		string port = "";
		fin >> port;
		fin >> url;
		while (!fin.eof()) {
			fin >> port;
			//cout << port << endl;
			fin >> url;
			//cout << url << endl;
			inQ.push(url);
		}
		fin.close();
		
		printf("Started batch mode with %d threads...\n", num_threads);
		printf("Reading input file... found %d entries...\n", size(inQ));
		p.mode = 2;

		total_tasks = size(inQ);

		// thread handles are stored here; they can be used to check status of threads, or kill them
		HANDLE *ptrs = new HANDLE[num_threads];

		// create a semaphore that counts the number of active threads
		p.finished = CreateSemaphoreA(NULL, 0, 1, NULL);
		p.eventQuit = CreateEventA(NULL, true, false, NULL);

		// initialize necessary shared parameter values
		p.inq = inQ;
		p.num_tasks = size(inQ);
		p.numSuccessful = 0;
		p.numNoAuth = 0;
		p.numNoDNS = 0;
		p.numTimeout = 0;
		p.numRetxAttempts = 0;
		p.totalDelay = 0;

		// get current time
		t = timeGetTime();

		// structure p is the shared space between the threads
		for (int i = 0; i < num_threads; i++) {
			ptrs[i] = CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)thread, &p, 0, NULL);
		}

		// make sure this thread hangs here until the other two quit; otherwise, the program will terminate prematurely
		for (int i = 0; i < num_threads; i++) {
			WaitForSingleObject(p.finished, INFINITE);
		}
	}

	if (p.mode == 2) {
		cout << "Completed " << total_tasks << " queries\n";
		cout << "	Successful: " << (p.numSuccessful / total_tasks) * 100 << "%" << endl;
		cout << "	No DNS record: " << (p.numNoDNS / total_tasks) * 100 << "%" << endl;
		cout << "	Local DNS timeout: " << (p.numTimeout / total_tasks) * 100 << "%" << endl;
		cout << "	Average delay: " << (p.totalDelay / total_tasks) << " ms" << endl;
		cout << "	Average retx attempts: " << (p.numRetxAttempts / total_tasks) << endl;
		cout << "Writing output file... finished\n";

		printf("Completed %d queries\n", total_tasks);
		printf("\t Successful: %.0f%%\n", (p.numSuccessful / total_tasks) * 100);
		printf("\t No DNS record: %.0f%%\n", (p.numNoDNS / total_tasks) * 100);
		printf("\t Local DNS timeout: %.0f%%\n", (p.numTimeout / total_tasks) * 100);
		printf("\t Average delay: %.0f ms\n", (p.totalDelay / total_tasks));
		printf("\t Average retx attempts: %.2f\n", (p.numRetxAttempts / total_tasks));
		printf("Writing output file... finished\n");
	}


	printf("-----------------\n");
	printf("Terminating main(), completion time %d ms\n", timeGetTime() - t);

	getchar();

	WSACleanup();

	return 0;
}

string makeBackwardsIP(string arg) {
	if (inet_addr(arg.c_str()) == INADDR_NONE) {
		printf("Invalid IP\n");
		return "";
	}
	string host = arg;
	string backwardsIP;
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
	host = backwardsIP + ".in-addr.arpa";
	return host;
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


// main function to resolve dns names
//   returns:
//           0 - Successfully found dns
//			 1 - No DNS found
//			 2 - Authoratative DNS not found
//			 3 - 
Parameters* resolveDNSbyName(string host, int arg_type, Parameters *p) {

	// print our primary/secondary DNS IPs
	DNS mydns;
	string dnsIP = "";
	mydns.printDNSServer(dnsIP);

	// set up the address of where we're sending data
	struct sockaddr_in send_addr;
	send_addr.sin_family = AF_INET;
	send_addr.sin_addr.S_un.S_addr = inet_addr(dnsIP.c_str()); // 208.67.222.222

	send_addr.sin_port = htons(53);

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

	char recv_buf[512];

	FD_SET Reader;
	FD_ZERO(&Reader);
	FD_SET(sock, &Reader);

	//set timeout for receive
	struct timeval timeout;
	timeout.tv_sec = 5; //set timeout for 10s
	timeout.tv_usec = 0;

	int recvbytes = 0;
	if (sentbytes > 0) {
		int count = 0; int sel;
		while (count < 3) {
			sel = select(sock, &Reader, NULL, NULL, &timeout);
			if (sel > 0) {
			
				recvbytes = recvfrom(sock, recv_buf, 512, 0, (struct sockaddr *) &send_addr, &send_addrSize);
				if (recvbytes >= 0) {
					break;
				}
				else {
					cout << "Thread " << GetCurrentThreadId() << "\n";
					cout << "Error reading..\n";
					closesocket(sock);
					delete[] pkt;
					return p;
				}
			}
			else if (sel == 0) {
				cout << "Thread " << GetCurrentThreadId() << "\n";
				cout << "Server timeout, retrying..." << endl;
			}
			else {
				cout << "Thread " << GetCurrentThreadId() << "\n";
				cout << "Error with select function, retrying..." << endl;
			}

			count++;
			EnterCriticalSection(&(p->count_mutex));
				p->numRetxAttempts++;
			LeaveCriticalSection(&(p->count_mutex));
		}
		closesocket(sock);
		if (count == 3) {
			cout << "Thread " << GetCurrentThreadId() << "\n";
			cout << "Too many timeouts. Abandoning IP.." << endl;
			EnterCriticalSection(&(p->count_mutex));
				p->numTimeout++;
			LeaveCriticalSection(&(p->count_mutex));
			delete[] pkt;
			return p;
		}
	}
	else
	{
		cout << "Thread " << GetCurrentThreadId() << "\n";
		cout << "No bytes were sent... \n";
		closesocket(sock);
		delete[] pkt;
		return p;
	}

	if (sentbytes == recvbytes) {
		cout << "Thread " << GetCurrentThreadId() << "\n";
		cout << "No answers returned...\n";
		closesocket(sock);
		delete[] pkt;
		return p;
	}
	//cout << "Thread " << GetCurrentThreadId() << ": recv bytes -> " << recvbytes << " | sentbytes: " << sentbytes << endl;
	u_char *reader = (u_char*) &recv_buf[pkt_size];

	FixedDNSheader * rDNS = (FixedDNSheader *)recv_buf;
	FixedRR ansRR;

	int end_idx = 0;

	string name = getName(reader, (u_char*)recv_buf, &end_idx);
	string rdata;
	//printf("Thread %d: name is -> %s\n", GetCurrentThreadId(), name);
	//cout << "Thread " << GetCurrentThreadId() << ": name is -> " << name << endl;
	reader = reader + end_idx;

	FixedRR *fixedrr = (FixedRR *)reader;
	reader = reader + sizeof(FixedRR);

	// read the rdata into
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
		rdata = getName(reader, (u_char*)recv_buf, &end_idx);
	}

	unsigned short rcode = 0x0F;
	rcode = rcode & ntohs(rDNS->flags);

	if (rcode == 3) {
		cout << "Thread " << GetCurrentThreadId();
		cout << "No DNS entry" << endl;
		EnterCriticalSection(&(p->count_mutex));
			p->numNoDNS++;
		LeaveCriticalSection(&(p->count_mutex));
		delete[] pkt;
		return p;
	}
	else if (rcode == 2) {
		cout << "Thread " << GetCurrentThreadId();
		cout << "Authoritative DNS server not found" << endl;
		EnterCriticalSection(&(p->count_mutex));
			p->numNoAuth++;
		LeaveCriticalSection(&(p->count_mutex));
		delete[] pkt;
		return p;
	}
	else if (rcode > 0) {
		cout << "Thread " << GetCurrentThreadId();
		cout << "Error type: " << rcode << endl;
		delete[] pkt;
		return p;
	}

	if (p->mode == 1)
		PrintResponse(name, rdata, rDNS, fixedrr);

	delete[] pkt;

	EnterCriticalSection(&(p->count_mutex));
		p->numSuccessful++;
	LeaveCriticalSection(&(p->count_mutex));

	return p;
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

void PrintResponse(string name, string rdata, FixedDNSheader *rDNS, FixedRR *fixedrr)
{
	cout << "Thread " << GetCurrentThreadId();
	cout << endl << endl << "Answer:" << endl;

	if (ntohs(fixedrr->type) == 5) {
		cout << "Thread " << GetCurrentThreadId();
		cout << name << " is aliased to " << rdata << endl;
	}
	else {
		cout << "Thread " << GetCurrentThreadId();
		cout << name << " is " << rdata << endl;
	}
}

void PrintStats(Parameters *p)
{
	cout << "Thread " << GetCurrentThreadId();
	cout << endl << endl << "Statistics:" << endl;


}
