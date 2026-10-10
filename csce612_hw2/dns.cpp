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
	MakeDNSQuestion((char *)(dns_header + 1), s);
	char * res = UDPCall(packet, pkt_size, server);
	delete[] packet;
    return res;
}

char* UDPCall(char* msg, int pkt_size, char *server)
{
    char* res = new char [MAX_DNS_LEN+1];
	int count = 0;
	int MAX_ATTEMPTS = 3;
    while (count++ < MAX_ATTEMPTS)
	{
		// send request to the server
		SOCKET sock = socket (AF_INET, SOCK_DGRAM, 0);
		if (sock == INVALID_SOCKET)
			ThrowWSAError("WSA error in assigning socket");

		struct sockaddr_in local;
		memset(&local, 0, sizeof(local));
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = INADDR_ANY;
		local.sin_port = htons(0);
		if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR)
			throw std::runtime_error("Error in bind UDP socket");
		
		struct sockaddr_in remote;
		memset(&remote, 0, sizeof(remote));
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = inet_addr(server);// server’s IP
		remote.sin_port = htons(53); // DNS port on server
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
			sockaddr from;
			int from_len = sizeof(from);
			//TODO: Do something with the returned from field
			int bytes = recvfrom(sock, res, MAX_DNS_LEN, 0, &from, &from_len);
			if (bytes == SOCKET_ERROR)
				ThrowWSAError("WSA error in recvfrom");
			if (bytes > MAX_DNS_LEN)
				throw std::runtime_error("exceeding MAX_DNS_LEN on response");

			res[bytes] = 0;

		}
		else if (available == 0)
		{
			if (count == MAX_ATTEMPTS)
				throw std::runtime_error("out of attempts");
		}
		else
			ThrowWSAError("WSA error in select");
		closesocket(sock);
	}
	return res;
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
