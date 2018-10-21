#include "headers.h"
#include "lookup.h"
#include <iostream>

Question::Question(void)  // constructor
{

};

// Packet visual:
// [ DNS Header - Question Buffer - Query Header ]
bool Question::MakePacket(char* pkt, FixedDNSheader &dnsheader, QueryHeader &queryheader)
{
	int size_pkt = strlen(pkt);
	int dhdr_size = sizeof(dnsheader);
	int qhdr_size = sizeof(queryheader);
	int buf_size = sizeof(rawbuffer);

	// add the dns header to pkt
	memcpy(pkt, &dnsheader, dhdr_size);

	// copy the mem from rawbuffer to pkt
	memcpy(pkt + dhdr_size, rawbuffer, buf_size);

	// add the query header to pkt
	//memcpy(pkt + size_pkt - qhdr_size, &queryheader, qhdr_size);

	return true;
}

bool Question::CreateQuestion(string host)
{
	// only creating the question, so only use size of question
	rawbuffer = new char[host.size() + 2];

	int position = host.find(".");
	string sub_str;

	int i = 0, sub_size = 0, hdr_size = sizeof(FixedDNSheader);

	// parse the host and place contents in packet
	host += ".";
	while (position != -1)
	{
		sub_size = position - i;
		sub_str = host.substr(i, position);

		rawbuffer[i] = sub_size;  // specify the size of the chunk (subdomain)
		i++;
		memcpy(rawbuffer + i, sub_str.c_str(), sub_size); // specify the actual subdomain

		i += sub_size;
		position = host.find(".", i);
	}
	rawbuffer[hdr_size + i] = 0;

	for (int i = 0; i < host.size() + 2; i++)
	{
		std::cout << "i= " << i << " " << rawbuffer[i] << endl;
	}
	getchar();

	return true;
}

int Question::Size() {
	return sizeof(rawbuffer);
}
