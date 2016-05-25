/*
 ************ UDP CLIENT CODE *******************
 * Adapted from Code Source: http://www.programminglogic.com/sockets-programming-in-c-using-udp-datagrams/
 * WARNING: Proof of Concept, only. Not tested for security or efficiency. 
 *
 * Original file header:
 *
 * Copyright (c) 2008 Amit Singh (osxbook.com).
 * http://osxbook.com/software/fslogger/
 *
 * Source released under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.0.
 * See http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt for details.
 *
 */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

// Socket Settings
#define MAX_IP 16
#define MAX_DATA 1024
#define MAX_SEND 65000
extern char    ip[MAX_IP];
extern int     port;

int clientSocket;
struct sockaddr_in serverAddr;
socklen_t addr_size;

// Functions
void set_dest(char *ip_addr, int dport);
void set_sock();
int send_packet(char *packet, int plen);
int send_udp(char *packet, int plen);
