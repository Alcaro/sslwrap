#if 0
g++ *.cpp -std=gnu++11 -DSSL=openssl -lssl -lcrypto
./a.out
exit
#endif

#include "socket.h"
#include <stdio.h>
#include <windows.h>


int main()
{
	/* create server socket and waits for client connection, returns client connection */
	Socket s = SocketCreateSSLSrv("localhost", 4433, true);
	if (s == NULL) {
		printf("can't create socket\n");
		return 1;
	}

	char data[512];
	do{
		int len = SocketGet(s, data, 511);
		if (len<0) break;
		data[len]='\0';
		fputs(data, stdout);
		SocketSend(s,
			"Pong Reply from GET / HTTP/1.1\r\n"
			"Host: www.google.ie\r\n"
			"Connection: close\r\n"
			"\r\n"
		);
		SocketClose(s);
	} while (false);
}
