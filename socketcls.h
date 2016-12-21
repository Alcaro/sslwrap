#pragma once

struct SocketCore {
	int fd;//for select()
	bool(*isActive)(SocketCore * thisCore, bool selected);
	//bool (*isOpen)(SocketCore * thisCore);
	int(*read)(SocketCore * thisCore, char * buf, int len);
	void(*write)(SocketCore * thisCore, const char * buf, int len, bool instant);
	void(*close)(SocketCore * thisCore);
};

SocketCore * NewRawConnection(const char * host, int port, int bytes = sizeof(SocketCore));