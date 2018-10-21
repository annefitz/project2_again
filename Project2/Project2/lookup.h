/*	lookup.h
	CPS 472 Sample Code
*/

/* query classes */
#define DNS_INET	1			/* the Internet */

// Query types are integer numbers specified in RFC 1035. Several useful queries:

/* DNS query types */
#define DNS_A			1		/* name -> IP */
#define DNS_NS			2		/* name server */
#define DNS_CNAME		5		/* canonical name */
#define DNS_PTR			12		/* IP->name */
#define DNS_HINFO		13		/* host info */
#define DNS_MX			15		/* mail exchange */
#define DNS_AXFR		252		/* request for zone transfer */
#define DNS_ANY			255		/* all records */


/* flags for the DNS header*/
#define DNS_QUERY		(0 << 15)		/* 0 = query; 1 = response */
#define DNS_RESPONSE	(1 << 15)

#define DNS_STDQUERY	(0)				/* opcode - 4 bits */
#define DNS_INVQUERY	(1 << 11)
#define DNS_SRVSTATUS	(1 << 12)

#define DNS_AA			(1 << 10)		/* authoritative answer */
#define DNS_TC			(1 << 9)		/* truncated */
#define DNS_RD			(1 << 8)		/* recursion desired */
#define DNS_RA			(1 << 7)		/* recursion available */


/* possible result codes  */
#define DNS_OK			0	/* rcode = reply codes */
#define DNS_FORMAT		1	/* format error (unable to interpret) */
#define DNS_SERVERFAIL	2	/* server failure */
#define DNS_ERROR		3	/* no DNS entry */
#define DNS_NOTIMPL		4	/* not implemented */
#define DNS_REFUSED		5	/* server refused the query */

// class defines the fixed query header
/* remember the current packing state */
#pragma pack(push)	// exact fit data into a structure with given size -- no padding
#pragma pack(1)
class QueryHeader{  // 4 bytes
public:
	u_short		type; 
	u_short		qclass;
};
/* now restore the previous packing state */
#pragma pack(pop)

// Fixed DNS header size: 
#pragma pack(push)	// exact fit data into a structure with given size -- no padding
#pragma pack(1)
class FixedDNSheader{	// 12 bytes
public:
	u_short ID;			// identification number

	// flags: 2 bytes
	u_short		flags;

	u_short		questions;		// number of question entries
	u_short		answers;		// number of answer entries
	u_short		authRRs;		// number of authority entries
	u_short		addRRs;			// number of resource entries
};
#pragma pack(pop)


#pragma pack(push)	// exact fit data into a structure with given size -- no padding
#pragma pack(1)		// because the struct is 10 bytes
class FixedRR {		// fixed header for RR
public:
	u_short		type; 
	u_short		RRclass;	//	 
	u_int		ttl;	// 4 bytes
	u_short		len;	// the length of the RDATA field
						// RDATA field: a variable length string that describes the resource
};
#pragma pack(pop)

class Question{
public: 
	char *rawbuffer;

	Question(void);			// constructor

	bool MakePacket(char* pkt, FixedDNSheader &dnsheader, QueryHeader &queryheader);

	bool CreateQuestion(string host);

	int Size();

};
