// csce612_hw2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// TODO:
// [x] Decide on the code-flow
// [x] Handle incorrect input
// [ ] Query types
// [ ] Build Query Constructor
// [ ] Build UDP socket mgmt
// [ ] Build Response parser
// [ ] Add retransmission on failures with 10s timeout
// [ ] Print output
//      [ ] Lookup : randomA.irl 
//	    [ ] Query : randomA.irl, type 1, TXID 0x8601
//	    [ ] Server : 128.194.135.82
//      [ ] 
//      [ ] Attempt 0 with 26 bytes... response in 1670 ms with 101 bytes
//      [ ] TXID 0xC101 flags 8183 questions 1 answers 0 authority 1 additional 0
//      [ ] failed with Rcode = 3
//      [ ] ++ invalid reply: TXID mismatch, sent 0x0871, received 0x0872

// Report: 
// [ ] Handle additional errors  
//      [ ] ++ invalid reply: packet smaller than fixed DNS header
//      [ ] ++ invalid section: not enough records (e.g., declared 5 answers but only 3 found)
//      [ ] ++ invalid record: jump beyond packet boundary
//      [ ] ++ invalid record: truncated name (e.g., “6 goog” and the packet ends)
//      [ ] ++ invalid record: truncated RR answer header (i.e., don’t have the full 10 bytes)
//      [ ] ++ invalid record: truncated jump offset (e.g., 0xC0 and the packet ends)
//      [ ] ++ invalid record: jump into fixed DNS header
//      [ ] ++ invalid record: jump loop
//      [ ] ++ invalid record: RR value length stretches the answer beyond packet

// Extra credit:
//  [ ] Reverse engineer algorithm used by random8.irl's response

#include "pch.h"
#include <iostream>

char* GenerateQuery(char* target, char* server, int type, bool reverse_lookup=false)
{
     
}

bool IsIP(char* query)
{
    unsigned long ret = inet_addr(query);
    return ret == INADDR_NONE ? false : true;
}

int main(int argc, char* argv[])
{
    // 1. Input formatting
    if (argc != 3)
    {
        printf("Incorrect usage, correct usage:\n");
        printf("csce512_hw2.exe <IP/Hostname> <DNS Server>");
		return 1;
    }
    try {
		WSAInit();

		// 2. Deciding if Reverse Query or not
        bool is_ip = IsIP(argv[1]);

		// 3. Build Query
        char* query = GenerateQuery(argv[1], argv[2], is_ip?12:1, is_ip);
		// 4. Make the request, get response
		// 5. Parse response
        WSACleanup();
    }
    catch (std::runtime_error& e)
    {
        printf("failed with %s", e.what());
        return 1;
    }
	return 0;
}
