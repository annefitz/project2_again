#include "headers.h"
#include "lookup.h"
#include <iostream>

Question::Question(void)  // constructor
{

};

/*
// Packet visual:
// [ DNS Header + Question Buffer + Query Header ]
bool Question::MakePacket(char* pkt, FixedDNSheader *dnsheader, QueryHeader *queryheader)
{
	int dhdr_size = sizeof(dnsheader);
	int qhdr_size = sizeof(queryheader);
	int buf_size = strlen(rawbuffer);

	// add the dns header to pkt
	//memcpy(pkt, &dnsheader, dhdr_size);

	// copy the mem from rawbuffer to pkt
	memcpy(pkt + dhdr_size, rawbuffer, buf_size);

	// add the query header to pkt
	//memcpy(pkt + dhdr_size + buf_size, &queryheader, qhdr_size);

	return true;
}
*/

bool Question::CreatePacket(string host, short arg_type, char * pkt, int pkt_size)
{
	FixedDNSheader * dHDR = (FixedDNSheader *)pkt;
	QueryHeader *qHDR = (QueryHeader*)(pkt + pkt_size - sizeof(QueryHeader));

	dHDR->ID = htons(102);
	dHDR->questions = htons(1);
	dHDR->addRRs = 0;
	dHDR->answers = 0;
	dHDR->authRRs = 0;
	dHDR->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);

	qHDR->qclass = htons(DNS_INET);

	int position = host.find(".");
	string sub_str;

	int i = 0, sub_size = 0, hdr_size = sizeof(FixedDNSheader);

	// parse the host and place contents in packet
	host += ".";
	while (position != -1)
	{
		sub_size = position - i;
		sub_str = host.substr(i, position);

		pkt[hdr_size + i] = sub_size;  // specify the size of the chunk (subdomain)
		i++;
		memcpy(pkt + hdr_size + i, sub_str.c_str(), sub_size); // specify the actual subdomain

		i += sub_size;
		position = host.find(".", i);
	}
	pkt[hdr_size + i] = 0;

	// if hostname
	if (arg_type == 2) {
		qHDR->type = htons(DNS_A);
	}
	// if IP
	else if (arg_type == 1) {
		qHDR->type = htons(DNS_PTR);  // for reverse dns lookup
		cout << "test";
	}

	return true;
}

