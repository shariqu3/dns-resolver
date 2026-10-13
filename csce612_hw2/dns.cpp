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

char* AskDnsQuery(char* host, char* server, int type, bool reverse_lookup)
{
    std::string s(host);
    if (reverse_lookup)
        MakeReverseHost(s);

	char *packet  = new char [MAX_DNS_LEN]; // 512 bytes is max
	int pkt_size = s.size() + 2 + sizeof(FixedDNSHeader) + sizeof(QueryHeader);

	FixedDNSHeader *dns_header = (FixedDNSHeader *) packet;
    dns_header->TXID = htons(-1);
    dns_header->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
    dns_header->n_questions = htons(1);
    dns_header->n_answers=htons(0);
    dns_header->n_authority=htons(0);
    dns_header->n_additional=htons(0);

    QueryHeader *query_header = (QueryHeader*) (packet + pkt_size - sizeof(QueryHeader));
    query_header->query_class = htons(DNS_INET);
    query_header->type= htons(type);

    printf("Lookup : %s\n", host);
    printf("Query  : %s, type %d, TXID 0x%04X\n", s.c_str(), ntohs(query_header->type), ntohs(dns_header->TXID));
	printf("Server : %s\n", server);
	printf("********************************\n");
	MakeDNSQuestion((char *)(dns_header + 1), s);
	int res_size;
	char * res = UDPCall(packet, pkt_size, server, res_size);
	DNSResponseParser((unsigned char *)res, res_size);
	delete[] packet;
    return res;
}

void DNSResponseParser(unsigned char* res, int pkt_size)
{		
	std::map<int, std::string> mp;
	mp[DNS_A] = "A";
	mp[DNS_NS] = "NS";
	mp[DNS_CNAME] = "CNAME";
	mp[DNS_MD] = "MD";
	mp[DNS_MF] = "MF";
	mp[DNS_SOA] = "SOA";
	mp[DNS_AXFR] = "AXFR";
	mp[DNS_ANY] = "ANY";
	mp[DNS_MB] = "MB";
	mp[DNS_MG] = "MG";
	mp[DNS_MR] = "MR";
	mp[DNS_NULL] = "NULL";
	mp[DNS_WKS] = "WKS";
	mp[DNS_PTR] = "PTR";
	mp[DNS_HINFO] = "HINFO";
	mp[DNS_MINFO] = "MINFO";
	mp[DNS_MX] = "MX";
	mp[DNS_TXT] = "TXT";

	FixedDNSHeader* res_header = (FixedDNSHeader*) res;
	int	cur_pos = sizeof(FixedDNSHeader);
	printf("  TXID 0x%04X, flags 0x%04X, questions %u, answers %u, authority %u, additional %u\n", ntohs(res_header->TXID), ntohs(res_header->flags), ntohs(res_header->n_questions), ntohs(res_header->n_answers), ntohs(res_header->n_authority), ntohs(res_header->n_additional));
	int rcode = ntohs(res_header->flags) % 16;
	if (!rcode)
		printf("  succeeded with Rcode = %d\n", rcode);
	else
	{
		printf("  failed with Rcode = %d", rcode);
		exit(1);
	}		

	PrintSectionRecords("questions", ntohs(res_header->n_questions), cur_pos, res, mp);
	PrintSectionRecords("answers", ntohs(res_header->n_answers), cur_pos, res, mp);
	PrintSectionRecords("authority", ntohs(res_header->n_authority), cur_pos, res, mp);
	PrintSectionRecords("additional", ntohs(res_header->n_additional), cur_pos, res, mp);
	delete[] res;
}

void PrintSectionRecords(const char* section_name, int n_entries, int &cur_pos, unsigned char* res, std::map<int, std::string>&mp)
{
	if (n_entries == 0)
		return;

	printf("  ------------ [%s] ----------\n", section_name);
	while(n_entries--)
		cur_pos = PrintResourceRecord(res, cur_pos, mp, false);
}

int PrintResourceRecord(unsigned char* ptr, int cur_pos, std::map<int, std::string> &mp, bool question)
{
	printf("\t");
	cur_pos = PrintDomainName(ptr, cur_pos);
	if (question)
	{
		printf(" type %u class %u\n", ntohs(*((u_short*)(ptr+cur_pos))), ntohs(*((u_short*)(ptr+cur_pos+2))));
		return cur_pos + 4;
	}
	else
	{
		DNSAnswerHeader *ans_header = (DNSAnswerHeader*)(ptr + cur_pos);
		cur_pos += sizeof(DNSAnswerHeader);
		switch (ntohs(ans_header->type))
		{
			case DNS_A:	
				if (ntohs(ans_header->len) != 4)
				{
					// TODO: Check if this needs to be displayed in different format
					throw std::runtime_error("Invalid length for type A response");
				}
				struct in_addr t;
				t.s_addr = *((unsigned long*)(ptr+cur_pos));
				printf(" %s %s TTL = %u\n", mp[ntohs(ans_header->type)].c_str(),  inet_ntoa(t), ntohl(ans_header->ttl));
				break;
			case DNS_CNAME:
			case DNS_NS:
			case DNS_PTR:
			default: 
				printf(" %s ", mp[ntohs(ans_header->type)].c_str());
				PrintDomainName(ptr, cur_pos);
				printf(" TTL = % u\n", ntohl(ans_header->ttl));
				break;
			
				//printf("skipped\n");
				break;
		}
		return cur_pos+ ntohs(ans_header->len);
	}
}

int PrintDomainName(unsigned char* ptr, int cur_pos)
{
	int cont_offset = -1;
	bool first_name = true;
	while (ptr[cur_pos] != 0)
	{
		if (ptr[cur_pos] >= 0xC0)
		{
			if (cont_offset == -1)
				cont_offset = cur_pos + 2;
			int off = ((ptr[cur_pos] & 0x3F) << 8) + ptr[cur_pos + 1];
			cur_pos = off;
		}
		else
		{
			int len = ptr[cur_pos];
			unsigned char cpy = ptr[cur_pos + len+1];
			ptr[cur_pos + len+1] = '\0';
			if (first_name)
				printf("%s", ptr + cur_pos + 1);
			else
				printf(".%s", ptr + cur_pos+1);
			ptr[cur_pos + len+1] = cpy;
			cur_pos += len+1;
			first_name = false;
		}
	}
	cur_pos++;
	if (cont_offset != -1)
		cur_pos = cont_offset;
	return cur_pos;
}


char* UDPCall(char* msg, int pkt_size, char *server, int &res_size)
{
    char* res = new char [MAX_DNS_LEN+1];
	int count = 0;
	int MAX_ATTEMPTS = 3;
	SOCKET sock = socket (AF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET)
		ThrowWSAError("WSA error in assigning socket");

	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(0);
	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR)
		ThrowWSAError("");

    while (count++ < MAX_ATTEMPTS)
	{
		printf("Attempt %d with %d bytes... ", count-1, pkt_size);
		Timer t;
		// send request to the server
		
		struct sockaddr_in remote;
		memset(&remote, 0, sizeof(remote));
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = inet_addr(server);// server’s IP
		// TODO: Change this back to 53
		remote.sin_port = htons(5300); // DNS port on server
		if (sendto(sock, msg, pkt_size, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR)
			throw std::runtime_error("Error in sending from UDP socket");

		// get ready to receive
		fd_set fd;
		FD_ZERO (&fd); // clear the set
		FD_SET (sock, &fd); // add your socket to the set
		const timeval* timeout = new timeval{10, 0};
		int available = select (0, &fd, NULL, NULL, timeout);
		if (available > 0)
		{
			sockaddr_in from;
			int from_len = sizeof(from);
			// TODO: Do something with the returned from field
			int bytes = recvfrom(sock, res, MAX_DNS_LEN, 0, (sockaddr *) & from, &from_len);
			//printf("From address: %s Remote address: %s\n", inet_ntoa(from.sin_addr), inet_ntoa(remote.sin_addr));
			if (from.sin_addr.s_addr != remote.sin_addr.s_addr)
				throw std::runtime_error("Response address doesn't match remote address");
			res_size = bytes;
			if (bytes == SOCKET_ERROR)
				ThrowWSAError("WSA error in recvfrom");
			if (bytes > MAX_DNS_LEN)
				throw std::runtime_error("exceeding MAX_DNS_LEN on response");
			res[bytes] = 0;
			printf("response in %ld ms with %d bytes\n", t.Elapsed(), bytes);
			break;
		}
		else if (available == 0)
		{
			printf("timeout in 10000ms\n");
			if (count == MAX_ATTEMPTS)
				throw std::runtime_error("out of attempts");
		}
		else
			ThrowWSAError("WSA error in select");
	}
	closesocket(sock);
	return res;
}

bool IsIP(char* query)
{
    return inet_addr(query) != INADDR_NONE;
}
