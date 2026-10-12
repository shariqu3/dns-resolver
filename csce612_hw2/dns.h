#pragma once
#include <string>
#include <Windows.h>
#include <map>

#define DNS_INET 1

/* DNS query types */
#define DNS_A 1 /* name -> IP */
#define DNS_NS 2 /* name server */
#define DNS_MD 3 
#define DNS_MF 4  
#define DNS_CNAME 5 /* canonical name */
#define DNS_PTR 12 /* IP -> name */
#define DNS_HINFO 13 /* host info/SOA */
#define DNS_MX 15 /* mail exchange */
#define DNS_AXFR 252 /* request for zone transfer */
#define DNS_ANY 255 /* all records */
#define DNS_SOA 6 
#define DNS_MB 7 
#define DNS_MG 8 
#define DNS_MR 9 
#define DNS_NULL 10 
#define DNS_WKS 11 
#define DNS_PTR 12 
#define DNS_HINFO 13 
#define DNS_MINFO 14 
#define DNS_MX 15 
#define DNS_TXT 16 

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
int PrintResourceRecord(unsigned char* ptr, int cur_pos, std::map<int, std::string> &mp, bool question = false);
