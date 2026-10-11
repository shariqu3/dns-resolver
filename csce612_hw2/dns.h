#pragma once
#include <string>
#include <Windows.h>

#define DNS_INET 1
/* flags */
#define DNS_QUERY (0 << 15) /* 0 = query; 1 = response */
#define DNS_RESPONSE (1 << 15)
#define DNS_STDQUERY (0 << 11) /* opcode - 4 bits */
#define DNS_AA (1 << 10) /* authoritative answer */
#define DNS_TC (1 << 9) /* truncated */
#define DNS_RD (1 << 8) /* recursion desired */
#define DNS_RA (1 << 7) /* recursion available */

const int MAX_DNS_LEN = 512;

void MakeReverseHost(std::string& s);
void MakeDNSQuestion(char* buf, std::string& host);
char* AskDnsQuery(char* host, char* server, int type, bool reverse_lookup = false);

#pragma pack(push,1)
struct QueryHeader
{
    u_short type;
    u_short query_class;
};

struct FixedDNSHeader 
{
    u_short TXID=-1;
    u_short flags=0;
    u_short n_questions=0;
    u_short n_answers=0;
    u_short n_authority=0;
    u_short n_additional=0;
};
struct DNSAnswerHeader{
u_short type;
u_short res_class;
u_int ttl;
u_short len;
};
#pragma pack(pop)

bool IsIP(char* query);
char* UDPCall(char* msg, int pkt_size, char* server, int &res_size);
void DNSResponseParser(unsigned char* res, int pkt_size);
unsigned char* PrintResourceRecord(unsigned char* ptr);
