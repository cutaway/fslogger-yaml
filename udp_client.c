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

#include "udp_client.h"

// Default ports
char ip[MAX_IP] = "127.0.0.1";
int  port       = 12345;

void set_dest(char *ip_addr, int dport){
    strncpy(ip,ip_addr,MAX_IP);
    port = dport;
}

//int set_sock(){
void set_sock(){

  /*Create UDP socket*/
  clientSocket = socket(PF_INET, SOCK_DGRAM, 0);

  /*Configure settings in address struct*/
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(port);
  serverAddr.sin_addr.s_addr = inet_addr(ip);
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

  /*Initialize size variable to be used later on*/
  addr_size = sizeof serverAddr;
}

int send_packet(char *packet, int plen){
    
  /*Send message to server*/
  sendto(clientSocket,packet,plen,0, (struct sockaddr *)&serverAddr,addr_size);

  return 0;
}

/*
 // Original function that does everything

int send_udp(char *packet, int plen){

  int clientSocket;
  struct sockaddr_in serverAddr;
  socklen_t addr_size;

  //Create UDP socket
  clientSocket = socket(PF_INET, SOCK_DGRAM, 0);

  //Configure settings in address struct
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(port);
  serverAddr.sin_addr.s_addr = inet_addr(ip);
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

  //Initialize size variable to be used later on
  addr_size = sizeof serverAddr;
    
  //Send message to server
  sendto(clientSocket,packet,plen,0, (struct sockaddr *)&serverAddr,addr_size);

  return 0;
}
*/
