// Mohammed Sharique CSCE-612 Fall 2026
#include "pch.h"


void ThrowWSAError(const char* msg)
{
	// NOTE: WSA Errors can be max of 5 digits
	size_t len = strlen(msg) + 5 + 2;
	char * buf = new char [len];
		SafeSNPrintf(buf, len, "%s %d", msg, WSAGetLastError());
	throw std::runtime_error(buf);
}

void WSAInit()
{
	WSADATA wsa_data;

	WORD wsa_ver_requested = MAKEWORD(2, 2);
	if (WSAStartup(wsa_ver_requested, &wsa_data) != 0) {
		ThrowWSAError("WSAStartup error");
		WSACleanup();
	}
}

Socket::Socket(int _max_download_size)
{
	buf = new char[INITIAL_BUF_SIZE]; 
	allocated_size = INITIAL_BUF_SIZE;
	cur_pos = 0;

	if (_max_download_size <= INITIAL_BUF_SIZE)
		throw std::runtime_error("maximum download size cannot be <= initial buffer size");
	
	max_download_size = _max_download_size;
	FD_ZERO(&fd);
	FD_SET(sock, &fd);

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		WSACleanup();
		ThrowWSAError("WSA error in socket");
	}
}

void Socket::Close()
{
	closesocket(sock);
}

void Socket::Connect(sockaddr_in& server, char* host, int port, bool print_steps)
{
	Timer t;
	server.sin_family = AF_INET;
	server.sin_port = htons(port);		

	int res = connect(sock, (struct sockaddr*)&server, sizeof(struct sockaddr_in));
	if (res == SOCKET_ERROR)
		ThrowWSAError("WSA error in connect");
	if(print_steps)
	printf("done in %ld ms\n", t.Elapsed());
}

void Socket::Read(void)
{
	int ret;
	Timer t = Timer();
	while (true)
	{
		FD_ZERO(&fd);
		FD_SET(sock, &fd);
		const timeval* timeout = new timeval{0, 10*1000*1000 - t.Elapsed()*1000};
		ret = select(0, &fd, nullptr, nullptr, timeout);
		delete timeout;
		if (ret > 0)
		{
			int bytes = recv(sock, buf + cur_pos, allocated_size - cur_pos, 0);
			if (bytes == SOCKET_ERROR)
				ThrowWSAError("WSA error in receive");

			else if (bytes == 0)
			{
				*(buf + cur_pos)= '\0';
				if (strncmp(buf, "HTTP/", 5) != 0)
					throw std::runtime_error("non-HTTP header (does not begin with HTTP/)");

				return;
			}

			cur_pos += bytes; 
			if(cur_pos>max_download_size)
				throw std::runtime_error("exceeding max");

			if(allocated_size - cur_pos < THRESHOLD)
			{
				allocated_size = min(2 * allocated_size, max_download_size+1);
				char* newBuf = new char[allocated_size];
				memcpy(newBuf, buf, cur_pos);
				delete[] buf;
				buf = newBuf;
			}
		}
		else if (ret==0)
			throw std::runtime_error("slow download");
		else
			ThrowWSAError("WSA error in select");
	}
}

void Socket::Send(char* buf)
{
	if (send(sock, buf, (int) strlen(buf), 0) == SOCKET_ERROR)
		ThrowWSAError("WSA error in send");
}
