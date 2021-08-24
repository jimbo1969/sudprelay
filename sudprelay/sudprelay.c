// Modifications for multicast receive by James Wing Aug 2021
// Note to self:  Debug stuff is set in launch.vs.json, loosely following this guide: https://unrealistic.dev/posts/setting-debug-parameters-with-cmake-tools-for-visual-studio
/*
	Copyright 2005,2006,2007,2008,2009 Luigi Auriemma

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

	http://www.gnu.org/licenses/gpl-2.0.txt
*/


#include "sudprelay.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include "acpdump2.h"
#include "show_dump.h"

#ifdef WIN32

//JW Aug 2021 -- the following lines needed for Windows sockets
#include <winsock2.h>
#include <Ws2ipdef.h>
#pragma comment(lib, "ws2_32.lib")
//#include "win_socket_stuff.h"
//end JW Aug 2021

#include "winerr.h"

#define close           closesocket
#define sleep           Sleep
#define in_addr_t       uint32_t
#define LOADDLL         hLib = LoadLibrary(fname); \
                            if(!hLib) winerr();
#define GETFUNC(x,y)    x = (void *)GetProcAddress(hLib, y); \
                            if(!quiet) printf("  %-10s %p\n", y, x);
//if(!x) winerr();
#define CLOSEDLL        FreeLibrary(hLib);
#define set_priority    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)
HINSTANCE   hLib = NULL;

void winerr(void);
#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <dlfcn.h>      // -ldl

#define LOADDLL         hLib = dlopen(fname, RTLD_LAZY); \
                            if(!hLib) { \
                                fprintf(stderr, "\nError: %s\n\n", dlerror()); \
                                exit(1); \
                            }
#define GETFUNC(x,y)    x = (void *)dlsym(hLib, y); \
                            if(!quiet) printf("  %-10s %p\n", y, (void*)x); // JW Aug 2021 - replaced below line with this for 64-bit compatibility
							//if(!quiet) printf("  %-10s %08x\n", y, (uint32_t)x);

#define CLOSEDLL        dlclose(hLib);
#define set_priority    nice(-10)
void* hLib = NULL;
#define SOCKET          int
#define SOCKET_ERROR    (-1)
#endif

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;


//#define VER         "0.4.1"	//JW Aug 2021 - moved this define to sudprelay.h and made it get defined dynamically via cmake
#define BUFFSZ      0xffff
#define RECVFROMF(X) \
                    psz = sizeof(struct sockaddr_in); \
                    len = recvfrom(X, buff, BUFFSZ, 0, (struct sockaddr *)&peerl, &psz); \
                    if(len < 0) continue;
#define SENDTOFC(X,Y) \
                    if(sendtof(sdl, buff, len, &c->peer, X) != len) { \
                        c = check_sd(&c->peer, 1); /* it's ever c->peer */ \
                        Y; \
                        if(!c) break; \
                    }

#ifndef IP_TOS
#define IP_TOS 3
#endif



// default: __cdecl
static int (*sudp_init)(u8*) = NULL;  // initialization
static int (*sudp_pck)(u8*, int) = NULL;  // modification of the packet
static int (*sudp_vis)(u8*, int) = NULL;  // modification for visualization only

static int (*myrecvfrom)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) = NULL;
static int (*mysendto)(SOCKET s, char** retbuf, int len, int flags, const struct sockaddr* to, int tolen) = NULL;


struct clients_struct {
	int     sd; // it's needed to use a different source port for each packet
	struct  sockaddr_in peer;
	time_t  timez;
	struct  clients_struct* next;
} *clients = NULL;

struct sockaddr_in* dhost = NULL;
in_addr_t   lhost = INADDR_ANY;
in_addr_t   mhost = INADDR_ANY;         //JW Aug 2021 - for multicast listener
in_addr_t   Lhost = INADDR_ANY;
int         multisock = 0;
int         samesock = 0;
int			quiet = 0;
int			timeout = 60;   // NAT uses a timeout of 5 minutes (300 seconds)
int			mc_boundary = 1;  //JW Aug 2021 - TTL/boundary of outbound multicast

// forward declarations
int sendtof(int s, char* buf, int len, struct sockaddr_in* to, int do_mysendto);
SOCKET bind_udp_socket(struct sockaddr_in* peer, in_addr_t iface, u16 port);    //JW Aug 2021 - changed return type from int to SOCKET
struct clients_struct* check_sd(struct sockaddr_in* peer, int force_remove);
struct sockaddr_in* create_peer_array(u8* list, u16 default_port);
void show_peer_array(u8* str, struct sockaddr_in* peer);
void loaddll(u8* fname, u8* par);
in_addr_t resolv(char* host);
void std_err(void);
int join_multicast_group(SOCKET sd, in_addr_t if_addr, in_addr_t mc_addr); //JW Aug 2021
int set_multicast_interface(SOCKET sd, in_addr_t mc_if, u8 ttl);    //JW Aug 2021


int main(int argc, char* argv[]) {
	struct	clients_struct* c = NULL;
	struct	clients_struct* tmpc;
	struct	sockaddr_in peerl;
	struct	sockaddr_in	peer0;
	struct	sockaddr_in* psrc = NULL;
	struct	sockaddr_in* pdst = NULL;
	struct  timeval tout;
	FILE*	fdcap = NULL;
	fd_set	readset;
	SOCKET	sdl = 0;
	SOCKET	sdi = 0;
	SOCKET	sd0 = 0;
	SOCKET	selsock = 0;
	int		i;
	int		len = 0;
	int		psz = 0;
	int		hexdump = 0;
	int		t;
	int		everyone = 0;
	int		priority = 0;
	u16     port;
	u16		lport;
	u16		inject = 0;
	u8      tmp[16];
	u8*		buff = NULL;
	u8*		acpfile = NULL;
	u8*		dllname = NULL;
	u8*		dllpar = NULL;

#ifdef WIN32
	WSADATA    wsadata;
	WSAStartup(MAKEWORD(1, 0), &wsadata);
#endif

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	fputs("\n"	
		"Simple UDP relay version "VER"\n"	//JW Aug 2021 - changed "proxy/pipe" to "relay" to distinguish this fork from original
		"by Luigi Auriemma\n"
		"e-mail: aluigi@autistici.org\n"
		"web:    aluigi.org\n"
		"... with multicast-enabling mods by James Wing - Aug 2021\n" //JW Aug 2021
		"\n", stderr);

	if (argc < 4) {
		printf("\n"
			"sudprelay: Listens to <local_port>, and forwards UDP datagrams to <server*> <server_port>\n\n" //JW Aug 2021 - resolve "server" ambiguity
			"Usage: %s [options] <server*> <server_port> <local_port>\n"
			"\n"
			"Options:\n"
			"-x       show the hex dump of each packet\n"
			"-a FILE  create a CAP (tcpdump) file in which storing all the packets\n"
			"-b IP    bind only the input interface identified with IP\n"
			"-B IP    as above but works only for the outgoing socket, this means you can\n"
			"         decide to use a secondary interface for connecting to the host (for\n"
			"         example using a wireless connection instead of the main one)\n"
			"         (always specify this outbound interface if sending multicast!)\n"    //JW Aug 2021 - otherwise sytem will guess based on interface metric
			"-l LIB   load a dll/so file which will be used to process all the incoming\n"
			"         packets. The library must contain the following __cdecl functions:\n"
			"           int sudp_init(char *data);          // if you need initialization\n"
			"           int sudp_pck(char *data, int len);  // each packet goes here\n"
			"           int sudp_vis(char *data, int len);  // for visualization only\n"
			"           int myrecvfrom(...cut...);          // proxocket plugin\n"
			"           int mysendto(...cut...);            // proxocket plugin\n"
			"-L PAR   parameter for the initialization of the above function,\n"
			"         if the plugin library supports parameters use -L \"\" for help/list\n"
			"-e       forward each packet to anyone (clients and server) except the sender,\n"
			"         it works just like a chat or a broadcaster\n"
			"-i PORT  injection option, listen on the port PORT and each packet received\n"
			"         here is sent to the server from all the connected clients\n"
			"-X       in case of multiple hosts assigns a new socket to each client, this\n"
			"         is useful if the hosts are the same for using multiple source ports\n"
			"-Y       just the opposite of the above one, ANY client has the same port\n"
			"-t SECS  seconds of inactivity after which closing the client socket (%d)\n"
			"-T TTL   TTL <integer> of *outbound* multicast // ignored if -B is not also set\n" //JW Aug 2021
			"         (see multicast TTL meaning:) 0=host, 1=subnet, 32=site, 64=region...\n"   //JW Aug 2021
			"         (default=1; meaningful iff <server> contains a multicast address)\n"      //JW Aug 2021
			"-m IP    multicast group (IPv4 address in the CIDR range 224.0.0.0/4)\n"           //JW Aug 2021
			"         to join via *listening* interface     // ignored if -b is not set\n"      //JW Aug 2021
			"-p       increase process priority\n"
			"-q       quiet output\n"
			"\n"
			"* <server> can be also a sequence of hostnames and IP addresses separated by\n"
			"  comma to which will be sent and received all the packets at the same time.\n"
			"  <server> can also contain the port using the syntax IP:PORT, such port will\n"
			"  override the default one set by <server_port>.\n"
			"  if <server> is 0 the tool will consider <server_port> as a local port and\n"
			"  will act just like a double binding mode (experimental!)\n"
			"\n", argv[0], timeout);
		exit(1);
	}

	argc -= 3;
	for (i = 1; i < argc; i++) {
		if (((argv[i][0] != '-') && (argv[i][0] != '/')) || (strlen(argv[i]) != 2)) {
			printf("\nError: wrong argument (%s)\n", argv[i]);
			exit(1);
		}
		switch (argv[i][1]) {
			case 'x': hexdump = 1;                      break;
			case 'a': acpfile = argv[++i];              break;
			case 'b': lhost = resolv(argv[++i]);        break;
			case 'B': Lhost = resolv(argv[++i]);        break;
			case 'l': dllname = argv[++i];              break;
			case 'L': dllpar = argv[++i];               break;
			case 'e': everyone = 1;                     break;
			case 'i': inject = atoi(argv[++i]);         break;
			case 'p': priority = 1;                     break;
			case 'q': quiet = 1;                        break;
			case 'X': multisock = 1;                    break;
			case 'Y': samesock = 1;                     break;
			case 't': timeout = atoi(argv[++i]);        break;
			case 'T': mc_boundary = atoi(argv[++i]);    break;  //JW Aug 2021 - for (outbound) multicast TTL/boundary
			case 'm': mhost = resolv(argv[++i]);        break;  //JW Aug 2021 - for (inbound) multicast join on listener

			default: {
				fprintf(stderr, "\nError: wrong command-line argument (%s)\n\n", argv[i]);
				exit(1);
			} break;
		}
	}

	port = atoi(argv[argc + 1]);                    //default sending/target port
	lport = atoi(argv[argc + 2]);                   //listening port
	dhost = create_peer_array(argv[argc], port);    //array of targets to send to

	if (lhost == INADDR_NONE) std_err();
	if (Lhost == INADDR_NONE) std_err();

	sdl = bind_udp_socket(NULL, lhost, lport);  //listening socket

	//JW Aug 2021 -- below added to join multicast group *on listening interface* if specified
	if (lhost && mhost) {   //if both -b and -m options were set and valid...
		if (!quiet) {
			char grp_name[INET_ADDRSTRLEN] = { 0 };
			if (inet_ntop(AF_INET, &mhost, grp_name, sizeof(grp_name)) != NULL) //inet_ntop is the modern approved replacement for inet_ntoa
				printf("- join multicast group %s\n", grp_name);
		}
		join_multicast_group(sdl, lhost, mhost);
	}
	//end JW Aug 2021

	if (inject) {
		sdi = bind_udp_socket(NULL, lhost, inject);
	}

	if (samesock) {
		if (!quiet) fprintf(stderr, "- same socket/port mode\n");
		samesock = bind_udp_socket(NULL, Lhost, 0);
		if (Lhost != INADDR_ANY) set_multicast_interface(samesock, Lhost, mc_boundary);   //JW Aug 2021
	}
	if (multisock) {
		if (!quiet) fprintf(stderr, "- multi socket/port mode\n");
	}

	if (!quiet) {
		if (dhost[0].sin_addr.s_addr) {
			show_peer_array("- remote hosts:  ", dhost);
		} else {
			fprintf(stderr, "- double binding\n");
			fprintf(stderr, "- dest_port      %hu\n", port);
		}
	}

	if (dllname) loaddll(dllname, dllpar);

	if (acpfile) {
		if (!quiet) printf("- create ACP file %s\n", acpfile);
		fdcap = fopen(acpfile, "rb");
		if (fdcap) {
			fclose(fdcap);
			fprintf(stderr, "- do you want to overwrite (Y) or append (A) the file? (y/a/N)\n  ");
			fgets(tmp, sizeof(tmp), stdin);
			t = tmp[0];
			if (t == 'a') {
			} else if (t == 'y') {
			} else return(0);
		}
		else {
			t = 0;
		}
		fdcap = fopen(acpfile, (t == 'a') ? "ab" : "wb");
		if (!fdcap) std_err();
		if (t != 'a') create_acp(fdcap);
	}

	if (priority) set_priority;

	if (!dhost[0].sin_addr.s_addr) {
		sd0 = bind_udp_socket(&peer0, Lhost, port);
		if (Lhost != INADDR_ANY) set_multicast_interface(sd0, Lhost, mc_boundary);   //JW Aug 2021
		printf("- wait first packet from the server (double-binding mode)\n");
		FD_ZERO(&readset);      // wait first client's packet, this is NEEDED!
		FD_SET(sd0, &readset);
		if (select(sd0 + 1, &readset, NULL, NULL, NULL)
			< 0) std_err();
	}

	printf("- ready\n");
	FD_ZERO(&readset);      // wait first client's packet, this is NEEDED!
	FD_SET(sdl, &readset);
	if (select(sdl + 1, &readset, NULL, NULL, NULL)
		< 0) std_err();

	buff = malloc(BUFFSZ);
	if (!buff) std_err();
	clients = NULL;

	for (;;) {
		FD_ZERO(&readset);
		FD_SET(sdl, &readset);
		selsock = sdl;
		if (sd0) {
			FD_SET(sd0, &readset);
			if (sd0 > selsock) selsock = sd0;
		}
		if (sdi) {
			FD_SET(sdi, &readset);
			if (sdi > selsock) selsock = sdi;
		}
		for (c = clients; c; c = c->next) {
			FD_SET(c->sd, &readset);
			if (c->sd > selsock) selsock = c->sd;
		}

		tout.tv_sec = timeout;     // this is useful if we want to free memory
		tout.tv_usec = 0;           // ...rarely used but I think it's good here
		t = select(selsock + 1, &readset, NULL, NULL, &tout);
		if (t < 0) std_err();
		if (!t) {    // timeout reached, call check_sd for removing the old clients
			memset(&peerl, 0, sizeof(struct sockaddr_in));
			check_sd(&peerl, 0);
			continue;
		}

		if (sdi && (FD_ISSET(sdi, &readset))) {
			RECVFROMF(sdi)

				if (!quiet) printf("- packet injection from %s:%hu (%d bytes)\n",
					inet_ntoa(peerl.sin_addr), ntohs(peerl.sin_port), len);

			psrc = &peerl;
			pdst = &dhost[0];   // the first one is enough, it's used only for the CAP file

			if (sudp_pck) len = sudp_pck(buff, len);  // packets modification

			for (c = clients; c; c = c->next) {
				if (sd0) sendtof(sd0, buff, len, &peer0, 1);
				for (i = 0; dhost[i].sin_addr.s_addr; i++) {
					sendtof(c->sd, buff, len, &dhost[i], 1);
				}
			}

			if (everyone) {
				for (c = clients; c; c = c->next) {
					SENDTOFC(1, )
				}
			}

		} else if (sd0 && FD_ISSET(sd0, &readset)) {    // experimental and useless
			RECVFROMF(sd0)

				psrc = &peerl;
			pdst = &peer0;  // yes it's wrong but it's not necessary

			if (sudp_pck) len = sudp_pck(buff, len);  // packets modification

			for (c = clients; c; c = c->next) {
				SENDTOFC(1, )
			}

			if (everyone) {
				// nothing to do here
			}
		} else if (FD_ISSET(sdl, &readset)) {
			RECVFROMF(sdl)

				c = check_sd(&peerl, 0);    // check if this is a new or existent client
			if (!c) continue;

			psrc = &c->peer;
			pdst = &dhost[0];   // the first one is enough, it's used only for the CAP file

			if (sudp_pck) len = sudp_pck(buff, len);  // packets modification

			if (sd0) sendtof(sd0, buff, len, &peer0, 1);
			if (multisock) {
				i = 0;
				for (c = clients; c; c = c->next) {
					if (!dhost[i].sin_addr.s_addr) break;
					if (memcmp(&c->peer, &peerl, sizeof(struct sockaddr_in))) continue;
					sendtof(c->sd, buff, len, &dhost[i], 1);
					i++;
				}
			} else {
				for (i = 0; dhost[i].sin_addr.s_addr; i++) {
					sendtof(c->sd, buff, len, &dhost[i], 1);
				}
			}

			if (everyone) {
				tmpc = c;
				for (c = clients; c; c = c->next) {
					if (c == tmpc) continue;
					SENDTOFC(1, )
				}
			}
		} else {
			for (c = clients; c; c = c->next) {
				if (!FD_ISSET(c->sd, &readset)) continue;
				RECVFROMF(c->sd)

					psrc = &peerl;
				pdst = &c->peer;

				if (sudp_pck) len = sudp_pck(buff, len);  // packets modification
				if (myrecvfrom) len = myrecvfrom(c->sd, buff, len, 0, (struct sockaddr*)psrc, &psz);

				SENDTOFC(0, pdst = NULL)    // like SENDTOFC but without the handling of mysendto

					if (everyone || samesock) {
						tmpc = c;
						for (c = clients; c; c = c->next) {
							if (c == tmpc) continue;
							SENDTOFC(1, )
						}
					}
				break;
			}
		}

		if (!psrc || !pdst) continue;    // the following is only for visualization

		if (fdcap) acp_dump(
			fdcap, SOCK_DGRAM, IPPROTO_UDP,
			psrc->sin_addr.s_addr, psrc->sin_port, pdst->sin_addr.s_addr, pdst->sin_port,
			buff, len,
			NULL, NULL, NULL, NULL);

		if (sudp_vis) len = sudp_vis(buff, len);

		if (hexdump) {
			if (!quiet) {
				printf("\n%s:%hu -> ", inet_ntoa(psrc->sin_addr), ntohs(psrc->sin_port));
				printf("%s:%hu\n", inet_ntoa(pdst->sin_addr), ntohs(pdst->sin_port));
			}
			show_dump(buff, len, stdout);
		}
	}

	close(sdl);
	if (sdi)   close(sdi);
	if (sd0)   close(sd0);
	if (fdcap) fclose(fdcap);
	if (hLib)  CLOSEDLL
		free(buff);
	return(0);
}



int sendtof(int s, char* buf, int len, struct sockaddr_in* to, int do_mysendto) {
	int     oldlen = 0,
		ret;
	char* oldbuf = NULL;

	if (!do_mysendto) {
		return(sendto(s, buf, len, 0, (struct sockaddr*)to, sizeof(struct sockaddr_in)));
	}

	if (mysendto) {
		oldbuf = buf;
		oldlen = len;
		ret = mysendto(s, &buf, len, 0, (struct sockaddr*)to, sizeof(struct sockaddr_in));
		if (ret >= 0) {
			// call real function
		} else if (ret == SOCKET_ERROR) {
			goto quit_and_free;
		} else {
			ret = oldlen;
			goto quit_and_free;
		}
		len = ret;
	}
	ret = sendto(s, buf, len, 0, (struct sockaddr*)to, sizeof(struct sockaddr_in));
quit_and_free:
	if (mysendto) {
		if (oldbuf != buf) free(buf);
		if (ret == len) ret = oldlen;
	}
	return(ret);
}



struct clients_struct* check_sd(struct sockaddr_in* peer, int force_remove) {
	struct clients_struct* c,
		* tmp,
		* prev,
		* ret;
	time_t  curr;
	int     multi = 0;

	curr = time(NULL);
	prev = NULL;
	ret = NULL;

	for (c = clients; c; ) {
		if ((c->peer.sin_addr.s_addr == peer->sin_addr.s_addr) && (c->peer.sin_port == peer->sin_port)) {
			c->timez = curr;
			ret = c;
			if (force_remove) {
				c->timez = (curr - timeout) - 1;
				ret = prev;
			}
		}
		if ((curr - c->timez) >= timeout) {
			if (!quiet) printf("- remove %s:%hu\n",
				inet_ntoa(c->peer.sin_addr), ntohs(c->peer.sin_port));

			tmp = c->next;
			if (samesock) {
				// do NOT close c->sd!
			} else {
				close(c->sd);
			}
			free(c);
			if (prev) {      // second, third and so on
				prev->next = tmp;
			} else {        // the first only
				clients = tmp;
			}
			c = tmp;        // already the next
		} else {
			prev = c;
			c = c->next; // get the next
		}
	}

	if (force_remove) return(ret);
	if (ret) return(ret);
	if ((peer->sin_addr.s_addr == INADDR_ANY) || (peer->sin_addr.s_addr == INADDR_NONE) || !peer->sin_port) return(NULL);

multisock_doit:
	c = malloc(sizeof(struct clients_struct));
	if (!c) return(NULL);
	if (prev) {
		prev->next = c;
	} else {
		clients = c;
	}

	if (samesock) {
		c->sd = samesock;
	} else {
		c->sd = bind_udp_socket(NULL, Lhost, 0);
		if (Lhost != INADDR_ANY) set_multicast_interface(c->sd, Lhost, mc_boundary);   //JW Aug 2021
	}
	memcpy(&c->peer, peer, sizeof(struct sockaddr_in));
	c->timez = curr;
	c->next = NULL;

	if (!quiet) printf("- add %s:%hu\n",
		inet_ntoa(c->peer.sin_addr), ntohs(c->peer.sin_port));

	if (multisock) {
		prev = c;
		multi++;
		if (dhost[multi].sin_addr.s_addr) goto multisock_doit;
	}

	return(c);
}



struct sockaddr_in* create_peer_array(u8* list, u16 default_port) {
	struct sockaddr_in* ret;
	int     i;
	int	size = 1;
	u16     port;
	u8* p1;
	u8* p2;

	for (p2 = list; (p1 = strchr(p2, ',')); size++, p2 = p1 + 1);

	ret = calloc(size + 1, sizeof(struct sockaddr_in));
	if (!ret) std_err();

	for (i = 0;;) {
		p1 = strchr(list, ',');
		if (p1) *p1 = 0;

		port = default_port;
		p2 = strchr(list, ':');
		if (p2) {
			*p2 = 0;
			port = atoi(p2 + 1);
		}

		while (*list == ' ') list++;
		ret[i].sin_addr.s_addr = resolv(list);
		ret[i].sin_port = htons(port);
		ret[i].sin_family = AF_INET;

		i++;
		if (!p1) break;
		list = p1 + 1;
	}
	return(ret);
}



void show_peer_array(u8* str, struct sockaddr_in* peer) {
	int     i;

	fputs(str, stderr);
	for (i = 0; peer[i].sin_addr.s_addr; i++) {
		if (i) fprintf(stderr, ", ");
		fprintf(stderr, "%s:%hu", inet_ntoa(peer[i].sin_addr), ntohs(peer[i].sin_port));
	}
	fputc('\n', stderr);
}


SOCKET bind_udp_socket(struct sockaddr_in* peer, in_addr_t iface, u16 port) {   //JW Aug 2021 - changed return type from int to SOCKET for Windows compatibility
	struct sockaddr_in  peer_tmp;
	int     sd;
	static const int
		on = 1,
		tos = 0x10;
	static const struct
		linger  ling = { 1,1 };

	if (!peer) peer = &peer_tmp;
	peer->sin_addr.s_addr = iface;
	peer->sin_port = htons(port);
	peer->sin_family = AF_INET;

	if ((iface != INADDR_ANY) || port) {
		if (!quiet) printf("- bind UDP port %hu on interface %s\n",
			ntohs(peer->sin_port), inet_ntoa(peer->sin_addr));
	}

	sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sd < 0) std_err();
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));
	if (bind(sd, (struct sockaddr*)peer, sizeof(struct sockaddr_in))
		< 0) std_err();

	setsockopt(sd, SOL_SOCKET, SO_LINGER, (char*)&ling, sizeof(ling));
	setsockopt(sd, SOL_SOCKET, SO_BROADCAST, (char*)&on, sizeof(on));
	setsockopt(sd, IPPROTO_IP, IP_TOS, (char*)&tos, sizeof(tos));

	return(sd);
}

//JW Aug 2021 - method to join multicast group for listening 
// Requires:
//  socket handle, sd
//  listener interface address, if_addr (specified by IPv4 address in dot-notation (e.g. "225.1.1.1"))
//  multicast group address, mc_addr (specified by IPv4 address in dot-notation (e.g. "225.1.1.1"))
// Returns:
//  0 for success, or not at all (like King Leonidas) upon failure
int join_multicast_group(SOCKET sd, in_addr_t if_addr, in_addr_t mc_addr) {
	struct ip_mreq group;
	group.imr_multiaddr.s_addr = mc_addr;
	group.imr_interface.s_addr = if_addr;
	if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&group, sizeof(group)) < 0) {
		fprintf(stderr, "\nError: unable to join multicast group (%s)\n", inet_ntoa(group.imr_multiaddr));
		close(sd);
		exit(1);
	}
	return 0;
}

//JW Aug 2021 - method to specify which interface should be used for *outbound* multicast datagrams
// Requires:
//  socket handle, sd
//  outbound multicast interface address, mc_if (derived from IPv4 address in dot-notation (e.g. "225.1.1.1") via inet_addr("225.1.1.1"))
//   --must be a local, multicast-capable interface
//  time-to-live, ttl - special meaning for multicast: 0=host; 1=subnet; 32=site; 64=regeon: 128=continent; 255=unrestricted
// Returns 0 on success
int set_multicast_interface(SOCKET sd, in_addr_t mc_if, u8 ttl) {
	struct in_addr local_interface;   //the local interface that is to be used for outbound multicast
	local_interface.s_addr = mc_if;
	u8 loop = 0;

	if (!quiet) {
		/*char interface_name[INET_ADDRSTRLEN] = { 0 };
		if (inet_ntop(AF_INET, &mc_if, interface_name, sizeof(interface_name)) != NULL)
			printf("- join multicast group %s\n", interface_name);*/
		printf("- setting outbound multicast TTL= %hu on interface %s\n", ttl, inet_ntoa(local_interface));
	}

	setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)); //disable loopback so we do not receive our own datagrams.
	setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
	setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, (char*)&local_interface, sizeof(local_interface));
	return 0;
}

void loaddll(u8* fname, u8* par) {
	if (!fname) return;

	printf("- load library %s\n", fname);

	LOADDLL;
	GETFUNC(sudp_init, "sudp_init");
	GETFUNC(sudp_pck, "sudp_pck");
	GETFUNC(sudp_vis, "sudp_vis");
	GETFUNC(myrecvfrom, "myrecvfrom");
	GETFUNC(mysendto, "mysendto");

	if (sudp_init && sudp_init(par)) {
		fprintf(stderr, "\nError: plugin initialization failed\n\n");
		CLOSEDLL
			exit(1);
	}
}


//resolves 'dot-notation' IPv4 address into a struct, which really can be represented by a simple unsigned 32-bit integer
in_addr_t resolv(char* host) {
	struct      hostent* hp;
	in_addr_t   host_ip;

	host_ip = inet_addr(host);
	if (host_ip == INADDR_NONE) {
		hp = gethostbyname(host);
		if (!hp) {
			fprintf(stderr, "\nError: unable to resolv hostname (%s)\n", host);
			exit(1);
		} else host_ip = *(in_addr_t*)hp->h_addr;
	}
	return(host_ip);
}



#ifndef WIN32
void std_err(void) {
	perror("\nError");
	exit(1);
}
#else
void winerr(void) {
	char* error;

	if (!FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&error,
		0,
		NULL)) {
		error = strerror(errno);
	}
	printf("\nError: %s\n", error);
	//LocalFree(error);
	exit(1);
}
#endif


