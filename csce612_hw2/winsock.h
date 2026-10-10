// Mohammed Sharique CSCE-612 Fall 2026
#pragma once

const int INITIAL_BUF_SIZE = 8 * 1024;
const int THRESHOLD= 2 * 1024;

class Socket {
public:
	SOCKET sock; 
	char* buf; 
	int allocated_size; 
	int cur_pos; 
	int max_download_size;
	fd_set fd;

	Socket(int max_download_size);
	virtual void Read(void);
	virtual void Connect(sockaddr_in& server, char* host, int port, bool print_steps=false);
	virtual void Send(char* buf);
	virtual void Close();
};


void WSAInit();
void ThrowWSAError(const char* msg);
