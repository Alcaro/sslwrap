#if 0
g++ *.cpp -std=gnu++11 -DSSL=openssl -lssl -lcrypto
./a.out
exit
#endif

#include "socket.h"
#include <stdio.h>

int main()
{
	Socket s = SocketCreateSSL("www.google.com", 443, false);
	SocketSend(s,
		"GET / HTTP/1.1\r\n"
		"Host: www.google.com\r\n"
		"Connection: close\r\n"
		"\r\n"
		);
	
	char data[512];
	while (true)
	{
		int len = SocketGet(s, data, 511);
		if (len<0) break;
		data[len]='\0';
		fputs(data, stdout);
	}
}
