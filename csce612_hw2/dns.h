#pragma once
#include <string>
#include <Windows.h>

const int MAX_DNS_LEN = 512;

void MakeReverseHost(std::string& s);
void MakeDNSQuestion(char* buf, std::string& host);
char* GenerateQuery(char* host, char* server, int type, bool reverse_lookup = false);

#pragma pack(push,1)
struct QueryHeader
{
    u_short type;
    u_short query_class;
    QueryHeader(u_short _type, u_short _query_class): type(_type), query_class(_query_class){}
};

struct FixedDNSHeader 
{
    u_short TXID=-1;
    u_short flags=0;
    u_short n_questions=0;
    u_short n_answers=0;
    u_short n_authority=0;
    u_short n_additional=0;

    FixedDNSHeader();
    FixedDNSHeader(char* res);

};
#pragma pack(pop)

bool IsIP(char* query);
