#pragma once
struct SocketCore;
typedef SocketCore* Socket;

//This one creates a raw TCP stream to a server and allows sending data back and forth.
Socket SocketCreate(const char * host, int port);

//This one opens an encrypted connection to the server. Usage rules are the same as NewConnection.
//Note that SSL support may not be universally present. The permissive flag makes it accept invalid
//certificates.
Socket SocketCreateSSL(const char * host, int port, bool permissive=false);

//This one makes SocketGet always return whole lines from the returned socket, and appends a \r\n
//(\n only if crlf is false) to every send operation. The input socket may not be used after that,
//not even to close it; closing the returned socket will take care of that. It is valid to use this
//on both encrypted and unencrypted sockets. Do not use it recursively, that will send blank lines.
//It is safe to use on a null socket; you'll get the null back.
Socket SocketWrapLine(Socket sock, bool crlf=true);

//This one finds a socket with waiting data (meaning SocketGet would return immediately and most
//likely give something useful). The return value is the index to the input array, or -1 if none was
//found within timeout seconds (timeout 0 is return instantly). Closed or broken sockets will always
//return activity; NULLs will never return activity. If you send only nulls (or a zero-length array,
//which is vacously only nulls), you'll call the system's sleeping function for the defined
//duration. Note that on some systems, it may return a false positive under some circumstances, so
//you should be prepared to handle zero bytes from the socket.
int SocketPoll(Socket * socks, int numsocks, int seconds);

//This one sends some data. It is binary safe if you pass the len parameter; otherwise, it expects a
//null terminated string. The entire message is always sent, though the function may block.
void SocketSend(Socket sock, const char * data, int len=0);

//This one sends the message and demands that the kernel does not wait for more data.
void SocketSendDirect(Socket sock, const char * data, int len=0);

//This one recieves some data from a socket. The return value is the number of bytes read. Note that
//it may refuse to return for a while if you didn't get it from SocketPoll, and that it can be zero
//bytes sometimes.
int SocketGet(Socket sock, char * data, int len);

//This one deletes a socket and frees its memory. After doing this, using the socket is undefined
//behaviour, so null it out. It is safe to close a null.
void SocketClose(Socket sock);

//This one creates a socket and sets it up to recieve connections. GetActiveSocket and SocketClose
//are valid operations on the returned socket, but SocketRead and SocketSend are invalid and will
//unconditionally return failure. If it's gotten from GetActiveSocket, SocketAccept will clear the
//ready state flag; the returned socket is equivalent to one from NewConnection. Each listening
//socket can accept multiple sockets; all returned sockets must be closed when you're done with
//them. Calling SocketAccept on a socket that's not from NewListenSocket is undefined behaviour.
Socket SocketCreateListen(const char * host, int port);
Socket SocketAccept(Socket sock);

//undocumented
const char * SocketGetIpFromHost(const char * domain);

#ifdef linux
//Use ONLY if you're up to no good.
int SocketGetFd(Socket sock);
Socket SocketCreateFromFd(int fd);

Socket SocketCreateUnix(const char * path);
Socket SocketCreateUnixListen(const char * path, int mode=0644);
#endif
