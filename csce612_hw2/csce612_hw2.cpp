// csce612_hw2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// TODO:
// [x] Decide on the code-flow
// [x] Handle incorrect input
// [x] Query types
// [x] Build Query Constructor
// [x] Build UDP socket mgmt
// [x] Build Response parser
//      [x] DNS_A 1 /* name -> IP */
//      [x] DNS_NS 2 /* name server */
//      [x] DNS_CNAME 5 /* canonical name */
//      [x] DNS_PTR 12 /* IP -> name */
// [ ] Build Response validator
// [x] Add retransmission on failures with 10s timeout
// [x] Print output
//      [x] Lookup : randomA.irl 
//	    [x] Query : randomA.irl, type 1, TXID 0x8601
//	    [x] Server : 128.194.135.82
//      [x] 
//      [x] Attempt 0 with 26 bytes... response in 1670 ms with 101 bytes
//      [x] TXID 0xC101 flags 8183 questions 1 answers 0 authority 1 additional 0
//      [x] failed with Rcode = 3

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
//      [ ] ++ invalid reply: TXID mismatch, sent 0x0871, received 0x0872

// Extra credit:
//  [ ] Reverse engineer algorithm used by random8.irl's response

#include "pch.h"
#include <iostream>
#include <string>

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
        char* server = argv[2];

		// 2. Deciding if Reverse Query or not
        bool is_ip = IsIP(argv[1]);

		// 3. Build Query
        char* res= AskDnsQuery(argv[1], argv[2], is_ip ? DNS_PTR: DNS_A, is_ip);

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
