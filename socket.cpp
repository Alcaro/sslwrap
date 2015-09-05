#include "socket.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#if defined(_WIN32)
	#define _WIN32_WINNT 0x501
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#define isagain(bytes) (bytes==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK)
	#define usleep(n) Sleep(n/1000)
	#define MSG_NOSIGNAL 0
	#define close closesocket
	#ifdef _MSC_VER
		#pragma comment(lib, "ws2_32.lib")
	#endif
#else
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <sys/un.h>
	#include <sys/stat.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <fcntl.h>
	#include <signal.h>
	#include <errno.h>
	#include <unistd.h>
	#define isagain(bytes) (bytes<0 && (errno==EAGAIN || errno==EWOULDBLOCK))
#endif



struct SocketCore {
	int fd;//for select()
	bool (*isActive)(SocketCore * thisCore, bool selected);
	//bool (*isOpen)(SocketCore * thisCore);
	int (*read)(SocketCore * thisCore, char * buf, int len);
	void (*write)(SocketCore * thisCore, const char * buf, int len, bool instant);
	void (*close)(SocketCore * thisCore);
};

/*
	core->write=[](SocketCore * thisCore, const char * data, int len)
	{
		RawSocketCore * core=(RawSocketCore*)thisCore;
		
	};
	core->read=[](SocketCore * thisCore, char * data, int len)->int
	{
		RawSocketCore * core=(RawSocketCore*)thisCore;
		
	};
	core->isActive=[](SocketCore * thisCore, bool selected)->bool
	{
		RawSocketCore * core=(RawSocketCore*)thisCore;
		
	};
	//core->isOpen=[](SocketCore * thisCore)->bool
	//{
	//	RawSocketCore * core=(RawSocketCore*)thisCore;
	//	
	//};
	core->close=[](SocketCore * thisCore)
	{
		RawSocketCore * core=(RawSocketCore*)thisCore;
		
	};
*/



#ifdef SSL
#define openssl 1686+0
#define schannel 1686+1

#if SSL==openssl
#define SSL_OPENSSL
#endif

#if SSL==schannel
#define SSL_SCHANNEL
#endif

#undef SSL
#undef openssl
#undef schannel
#endif



#ifdef SSL_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
//#include <openssl/bio.h>

static SSL_CTX * sslContext;
#endif



#ifdef SSL_SCHANNEL
static void LoadSecurityLibrary();
#endif


static bool initialized=false;




static void initialize()
{
	if (initialized) return;
	initialized=true;
	
#ifdef _WIN32
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
#ifdef linux
	signal(SIGPIPE, SIG_IGN);
#endif
#ifdef SSL_OPENSSL
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	sslContext=SSL_CTX_new(SSLv23_client_method());
#endif
#ifdef SSL_SCHANNEL
	LoadSecurityLibrary();
#endif
}

int SocketGet(Socket sock, char * data, int len)
{
	return sock->read(sock, data, len);
}

void SocketSend(Socket sock, const char * data, int len)
{
	if (len==0) len=strlen(data);
	sock->write(sock, data, len, false);
}

void SocketSendDirect(Socket sock, const char * data, int len)
{
	if (len==0) len=strlen(data);
	sock->write(sock, data, len, true);
}

void SocketClose(Socket sock)
{
	if (!sock) return;
	sock->close(sock);
	free(sock);
}



static void SetSocketBuffering(int fd, bool buffer)
{
//#ifdef linux
	int flag=(!buffer);
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
//#endif
}

static void SetSocketVTable(SocketCore * core)
{
	core->write=[](SocketCore * thisCore, const char * data, int len, bool instant)
	{
		SocketCore * core=(SocketCore*)thisCore;
		if (core->fd==-1) return;
		if (instant) SetSocketBuffering(core->fd, false);
		while (len)
		{
			int thislen=send(core->fd, data, len, 0);
			if (thislen<=0)
			{
				if (isagain(thislen))
				{
					usleep(100000);
					continue;
				}
				core->close(core);
				return;
			}
			data+=thislen;
			len-=thislen;
		}
		if (instant) SetSocketBuffering(core->fd, true);
	};
	core->read=[](SocketCore * thisCore, char * data, int len)->int
	{
		SocketCore * core=(SocketCore*)thisCore;
		if (core->fd==-1) return -1;
		int bytes=recv(core->fd, data, len, 0);
		if (bytes==0)
		{
			core->close(core);
			return -1;
		}
		if (isagain(bytes)) return 0;
		return bytes;
	};
	core->isActive=[](SocketCore * thisCore, bool selected)->bool
	{
		SocketCore * core=(SocketCore*)thisCore;
		if (core->fd==-1) return true;
		return selected;
	};
	core->close=[](SocketCore * thisCore)
	{
		SocketCore * core=(SocketCore*)thisCore;
		if (core->fd==-1) return;
		close(core->fd);
		core->fd=-1;
	};
}

static void SetSocketVTableNull(SocketCore * core)
{
	core->write=[](SocketCore * thisCore, const char * data, int len, bool instant) {};
	core->read=[](SocketCore * thisCore, char * data, int len)->int { return -1; };
	core->isActive=[](SocketCore * thisCore, bool selected)->bool { return selected; };
	core->close=[](SocketCore * thisCore)
	{
		SocketCore * core=(SocketCore*)thisCore;
		if (core->fd==-1) return;
		close(core->fd);
		core->fd=-1;
	};
}

static SocketCore * NewRawConnection(const char * host, int port, int bytes=sizeof(SocketCore))
{
	initialize();
	
	char portstr[16];
	sprintf(portstr, "%i", port);
	
	addrinfo hints;
	memset(&hints, 0, sizeof(addrinfo));
	hints.ai_family=AF_UNSPEC;
	hints.ai_socktype=SOCK_STREAM;
	hints.ai_flags=0;
	
	//Ip ip;
	//ip.core=(IpCore*)malloc(sizeof(IpCore));
	//ip.core->refcount=1;
	//ip.core->serverinfo=NULL;
	addrinfo * addr=NULL;
	getaddrinfo(host, portstr, &hints, &addr);
	if (!addr) return NULL;
	
	SocketCore * core=(SocketCore*)malloc(bytes);
	memset(core, 0, bytes);
	core->fd=socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
#ifndef _WIN32
	//because 30 second pauses are unequivocally detestable
	timeval timeout;
	timeout.tv_sec=4;
	timeout.tv_usec=0;
	setsockopt(core->fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof timeout);
#endif
	if (connect(core->fd, addr->ai_addr, addr->ai_addrlen)!=0)
	{
		freeaddrinfo(addr);
		close(core->fd);
		free(core);
		return NULL;
	}
	freeaddrinfo(addr);
#ifndef _WIN32
	//because Linux obviously doesn't know that select() should only give sockets where read() is nonblocking
	fcntl(core->fd, F_SETFL, fcntl(core->fd, F_GETFL, 0)|O_NONBLOCK);
#endif
	//core.core->open=true;
	SetSocketVTable(core);
	return core;
}

Socket SocketCreate(const char * host, int port)
{
	return (Socket)NewRawConnection(host, port);
}

int SocketPoll(Socket * socks, int numsocks, int seconds)
{
	fd_set fds;
	FD_ZERO(&fds);
	bool anysocks=false;
	for (int i=0;i<numsocks;i++)
	{
		if (socks[i])
		{
			anysocks=true;
			if (socks[i]->isActive(socks[i], false)) return i;
			if (socks[i]->fd!=-1) FD_SET(socks[i]->fd, &fds);
		}
	}
	if (!anysocks)
	{
		usleep(seconds*1000000);
		return -1;
	}
	timeval timeout;
	timeout.tv_sec=seconds;
	timeout.tv_usec=0;
	select(FD_SETSIZE, &fds, NULL, NULL, &timeout);
	for (int i=0;i<numsocks;i++)
	{
		SocketCore * core=socks[i];
		if (socks[i] && core->fd!=-1 && FD_ISSET(core->fd, &fds) && core->isActive(core, true)) return i;
	}
	return -1;
}

const char * SocketGetIpFromHost(const char * domain)
{
	initialize();
	
	addrinfo hints;
	memset(&hints, 0, sizeof(addrinfo));
	hints.ai_family=AF_UNSPEC;
	hints.ai_socktype=0;
	hints.ai_flags=0;
	
	addrinfo * addr=NULL;
	getaddrinfo(domain, NULL, &hints, &addr);
	if (!addr) return NULL;
	
	//const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);
	
	struct sockaddr* address=addr->ai_addr;
	const char * ret=NULL;
	static char buf[INET6_ADDRSTRLEN];
	
#ifdef linux
	if (addr->ai_family==AF_INET)
	{
		ret=inet_ntop(AF_INET, &(((struct sockaddr_in *)address)->sin_addr), buf, INET_ADDRSTRLEN);
	}
	
	if (addr->ai_family==AF_INET6)
	{
		ret=inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)address)->sin6_addr), buf, INET6_ADDRSTRLEN);
	}
#else
	DWORD shutup=INET6_ADDRSTRLEN;
	if (WSAAddressToString(address, addr->ai_addrlen, NULL, buf, &shutup)==0) ret=buf;
#endif
	
	freeaddrinfo(addr);
	return ret;
}




struct LineSocketCore : SocketCore {
	SocketCore * nextCore;
	char * linebuf;
	int linebuflen;
	int lineend;//this one points to the first \n or \0 in linebuf, whichever comes first
	void (*prepareLine)(SocketCore * thisCore);
	bool crlf;
};

Socket SocketWrapLine(Socket sock, bool crlf)
{
	if (!sock) return sock;
	LineSocketCore * core=(LineSocketCore*)malloc(sizeof(LineSocketCore));
	core->nextCore=(SocketCore*)sock;
	core->linebuf=(char*)malloc(sizeof(char)*256);
	core->linebuf[0]='\0';
	core->linebuflen=256;
	core->lineend=0;
	core->fd=sock->fd;
	core->crlf=crlf;
	core->prepareLine=[](SocketCore * thisCore)
	{
		LineSocketCore * core=(LineSocketCore*)thisCore;
		if (core->fd==-1) return;
		if (core->linebuf[core->lineend]=='\n') return;
		if (core->linebuflen-core->lineend<256)
		{
			core->linebuflen*=2;
			core->linebuf=(char*)realloc(core->linebuf, core->linebuflen);
		}
		int newbytes=core->nextCore->read(core->nextCore, core->linebuf+core->lineend, core->linebuflen-core->lineend-1);
		if (newbytes<0)
		{
			core->close(core);
			return;
		}
		core->linebuf[core->lineend+newbytes]='\0';
		while (core->linebuf[core->lineend] && core->linebuf[core->lineend]!='\n') core->lineend++;
	};
	core->write=[](SocketCore * thisCore, const char * data, int len, bool instant)
	{
		LineSocketCore * core=(LineSocketCore*)thisCore;
		if (core->fd==-1) return;
		core->nextCore->write(core->nextCore, data, len, false);
		if (core->crlf) core->nextCore->write(core->nextCore, "\r\n", 2, instant);
		else core->nextCore->write(core->nextCore, "\n", 1, instant);
	};
	core->read=[](SocketCore * thisCore, char * data, int len)->int
	{
		LineSocketCore * core=(LineSocketCore*)thisCore;
		if (core->fd==-1) return -1;
		*data=0;
		core->prepareLine(core);
		if (core->fd==-1) return -1;
		if (core->linebuf[core->lineend]!='\n') return 0;
		int linelen=core->lineend;
		if (len<=linelen) return -1;
		memcpy(data, core->linebuf, linelen);
		memmove(core->linebuf, core->linebuf+linelen+1, strlen(core->linebuf+linelen+1)+1);
		for (core->lineend=0;core->linebuf[core->lineend] && core->linebuf[core->lineend]!='\n';core->lineend++);
		if (linelen && data[linelen-1]=='\r') linelen--;
		data[linelen]=0;
		return linelen;
	};
	core->isActive=[](SocketCore * thisCore, bool selected)->bool
	{
		LineSocketCore * core=(LineSocketCore*)thisCore;
		if (core->fd==-1) return true;
		if (selected) core->prepareLine(core);
		if (core->fd==-1) return true;
		return (core->linebuf[core->lineend]=='\n');
	};
	//core->isOpen=[](SocketCore * thisCore)->bool
	//{
	//	LineSocketCore * core=(LineSocketCore*)thisCore;
	//	if (core->fd==-1) return false;
	//	return core->nextCore->isOpen(core->nextCore);
	//};
	core->close=[](SocketCore * thisCore)
	{
		LineSocketCore * core=(LineSocketCore*)thisCore;
		if (core->fd==-1) return;
		SocketClose(core->nextCore);
		free(core->linebuf);
		core->fd=-1;
	};
	return core;
}



struct ListenSocketCore : SocketCore {
	//null
};

Socket SocketCreateListen(const char * host, int port)
{
	initialize();
	
	char portstr[16];
	sprintf(portstr, "%i", port);
	
	addrinfo hints;
	memset(&hints, 0, sizeof(addrinfo));
	hints.ai_family=AF_UNSPEC;
	hints.ai_socktype=SOCK_STREAM;
	hints.ai_flags=0;
	
	//Ip ip;
	//ip.core=(IpCore*)malloc(sizeof(IpCore));
	//ip.core->refcount=1;
	//ip.core->serverinfo=NULL;
	addrinfo * addr=NULL;
	getaddrinfo(host, portstr, &hints, &addr);
	if (!addr) return NULL;
	
	ListenSocketCore * core=(ListenSocketCore*)malloc(sizeof(ListenSocketCore));
	memset(core, 0, sizeof(ListenSocketCore));
	core->fd=socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
#ifndef _WIN32
	//because 30 second pauses are unequivocally detestable
	timeval timeout;
	timeout.tv_sec=4;
	timeout.tv_usec=0;
	setsockopt(core->fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof timeout);
#endif
	if (bind(core->fd, addr->ai_addr, addr->ai_addrlen)!=0 || listen(core->fd, 10)!=0)
	{
		freeaddrinfo(addr);
		close(core->fd);
		free(core);
		return NULL;
	}
	freeaddrinfo(addr);
	SetSocketVTableNull(core);
	return core;
}

Socket SocketAccept(Socket sock)
{
	int fd=accept(sock->fd, NULL, NULL);
	SocketCore * core=(SocketCore*)malloc(sizeof(SocketCore));
	SetSocketVTable(core);
	core->fd=fd;
	return core;
}


#ifdef linux
int SocketGetFd(Socket sock)
{
	if (!sock) return -1;
	return sock->fd;
}

Socket SocketCreateFromFd(int fd)
{
	if (fd<0) return NULL;
	SocketCore * core=(SocketCore*)malloc(sizeof(SocketCore));
	memset(core, 0, sizeof(SocketCore));
	core->fd=fd;
	SetSocketVTable(core);
	return core;
}

Socket SocketCreateUnix(const char * path)
{
	initialize();
	
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family=AF_UNIX;
	strcpy(addr.sun_path, path);
	
	SocketCore * core=(SocketCore*)malloc(sizeof(SocketCore));
	memset(core, 0, sizeof(SocketCore));
	core->fd=socket(AF_UNIX, SOCK_STREAM, 0);
	if (connect(core->fd, (sockaddr*)&addr, SUN_LEN(&addr))!=0)
	{
		close(core->fd);
		free(core);
		return NULL;
	}
	SetSocketVTable(core);
	return core;
}

Socket SocketCreateUnixListen(const char * path, int mode)
{
	initialize();
	
	unlink(path);
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family=AF_UNIX;
	strcpy(addr.sun_path, path);
	
	ListenSocketCore * core=(ListenSocketCore*)malloc(sizeof(ListenSocketCore));
	memset(core, 0, sizeof(ListenSocketCore));
	core->fd=socket(AF_UNIX, SOCK_STREAM, 0);
	if (bind(core->fd, (sockaddr*)&addr, SUN_LEN(&addr))!=0 || listen(core->fd, 10)!=0)
	{
		close(core->fd);
		free(core);
		return NULL;
	}
	chmod(path, mode);
	SetSocketVTableNull(core);
	return core;
}
#endif


#if defined(SSL_OPENSSL)
struct SSLSocketCore : SocketCore {
	SSL * sslHandle;
};

static bool PrepareSSLConnection(SSLSocketCore* core, bool permissive)
{
	core->sslHandle=SSL_new(sslContext);
	if (!core->sslHandle) goto fail;
	if (!SSL_set_fd(core->sslHandle, core->fd)) goto fail;
	
	while (true)
	{
		int connecterr=SSL_connect(core->sslHandle);
		if (connecterr==1) break;
		if (SSL_get_error(core->sslHandle, connecterr)==SSL_ERROR_WANT_READ || SSL_get_error(core->sslHandle, connecterr)==SSL_ERROR_WANT_WRITE)
		{
			usleep(100000);
			continue;
		}
		else goto fail;
	}
	
//	if (!permissive)
//	{
//		int certerror=SSL_get_verify_result(core->sslHandle);
//printf("/%i/", certerror);
//		if (certerror) goto fail;
//	}
	
	core->write=[](SocketCore * thisCore, const char * data, int len, bool instant)
	{
		SSLSocketCore * core=(SSLSocketCore*)thisCore;
		if (core->fd==-1) return;
		while (len)
		{
			int thislen=SSL_write(core->sslHandle, data, len);
			if (thislen<=0)
			{
				if (SSL_get_error(core->sslHandle, thislen)==SSL_ERROR_WANT_READ || SSL_get_error(core->sslHandle, thislen)==SSL_ERROR_WANT_WRITE)
				{
					usleep(100000);
					continue;
				}
				else
				{
					core->close(core);
				}
			}
			data+=thislen;
			len-=thislen;
		}
	};
	core->read=[](SocketCore * thisCore, char * data, int len)->int
	{
		SSLSocketCore * core=(SSLSocketCore*)thisCore;
		if (core->fd==-1) return -1;
		int bytes=SSL_read(core->sslHandle, data, len);
		if (bytes<=0)
		{
			int sslerror=SSL_get_error(core->sslHandle, bytes);
//printf("-- SSL ERROR %i '%s'\n", sslerror, ERR_error_string(sslerror, NULL));
//ERR_print_errors_fp(stdout);
//printf("\nEOF\n");
			if (sslerror==SSL_ERROR_WANT_READ || sslerror==SSL_ERROR_WANT_WRITE)
			{
//printf("-- SSL ERROR %i - IGNORED\n", sslerror);
				return 0;
			}
			else if (sslerror==SSL_ERROR_ZERO_RETURN ||
				(sslerror==SSL_ERROR_SYSCALL && bytes<=0))
			{
//printf("-- SSL ERROR %i - CLEAN EXIT\n", sslerror);
				core->close(core);
				return -1;
			}
			else
			{
printf("-- SSL ERROR %i(%i) - CLOSING\n", sslerror, bytes);
ERR_print_errors_fp(stdout);
				core->close(core);
				return -1;
			}
		}
		return bytes;
	};
	core->isActive=[](SocketCore * thisCore, bool selected)->bool
	{
		SSLSocketCore * core=(SSLSocketCore*)thisCore;
		if (core->fd==-1) return true;
		return selected;
	};
	core->close=[](SocketCore * thisCore)
	{
		SSLSocketCore * core=(SSLSocketCore*)thisCore;
		if (core->fd==-1) return;
		if (core->sslHandle)
		{
			SSL_shutdown(core->sslHandle);
			SSL_free(core->sslHandle);
		}
		close(core->fd);
		core->fd=-1;
	};
	return true;
	
fail:
	if (core->sslHandle)
	{
		SSL_shutdown(core->sslHandle);
		SSL_free(core->sslHandle);
	}
	return false;
}

Socket SocketCreateSSL(const char * host, int port, bool permissive)
{
	initialize();
	if (!sslContext) return NULL;
	
	SSLSocketCore * core=(SSLSocketCore*)NewRawConnection(host, port, sizeof(SSLSocketCore));
	if (!core) return NULL;
	if (!PrepareSSLConnection(core, permissive))
	{
		close(core->fd);
		free(core);
		return NULL;
	}
	return core;
}




#elif defined(SSL_SCHANNEL)
#include "socket-ssl-schannel.cpp"
#else
Socket SocketCreateSSL(const char * host, int port, bool permissive)
{
	return NULL;
}
#endif
