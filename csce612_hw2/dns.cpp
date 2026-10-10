#include "pch.h"

void MakeReverseHost(std::string &s)
{

    std::string::iterator itr = s.begin();
    for(auto i = s.begin(); i!=s.end();i++)
    {
        if (*i == '.')
        {
            std::reverse(itr, i);
			itr = i+1;
        }
    }
	std::reverse(itr, s.end());
	std::reverse(s.begin(), s.end());
    s += ".in-addr.arpa";
}

void MakeDNSQuestion(char* buf, std::string &host)
{
    char* str = host.data();
    char* nxt = nullptr;
    int i = 0;
    while (nxt = strchr(str, '.'))
    {
        *nxt = '\0';
        int len = strlen(str);
		buf[i++] = ((char*)(&len))[0];
        memcpy(buf + i, str, len);
        i += len;
        str = nxt + 1;
    }
	int len = strlen(str);
    buf[i++] = ((char*)(&len))[0];
	memcpy(buf + i, str, len);
	i += len;
    buf[i] = '\0';
}

char* GenerateQuery(char* host, char* server, int type, bool reverse_lookup)
{
    std::string s(host);
    if (reverse_lookup)
        MakeReverseHost(s);

	char *packet  = new char [MAX_DNS_LEN]; // 512 bytes is max
	int pkt_size = s.size() + 2 + sizeof(FixedDNSHeader) + sizeof(QueryHeader);

	FixedDNSHeader *dns_header = (FixedDNSHeader *) packet;
    dns_header->TXID = htons(-1);
    dns_header->flags = htons(1 << 8);
    dns_header->n_questions = htons(1);
    dns_header->n_answers=0;
    dns_header->n_authority=0;
    dns_header->n_additional=0;

    QueryHeader *query_header = (QueryHeader*) (packet + pkt_size - sizeof(QueryHeader));
    query_header->query_class = htons(1);
    query_header->type= htons(type);

    printf("Lookup : %s\n", host);
    printf("Query  : %s, type %d, TXID 0x%04X\n", s.c_str(), ntohs(query_header->type), ntohs(dns_header->TXID));
	MakeDNSQuestion((char *)(dns_header + 1), s);
    return packet;
}

FixedDNSHeader::FixedDNSHeader()
{ 
	TXID = rand();
	flags |=  1 << 8;
	n_questions = htons(1);
}

FixedDNSHeader::FixedDNSHeader(char* res){
	// parse response into the header
}

bool IsIP(char* query)
{
    return inet_addr(query) != INADDR_NONE;
}
