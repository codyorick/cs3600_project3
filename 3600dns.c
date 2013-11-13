/*
 * CS3600, Fall 2013
 * Project 3 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#include <math.h>
#include <ctype.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "3600dns.h"

/**
 * This function will print a hex dump of the provided packet to the screen
 * to help facilitate debugging.  In your milestone and final submission, you 
 * MUST call dump_packet() with your packet right before calling sendto().  
 * You're welcome to use it at other times to help debug, but please comment those
 * out in your submissions.
 *
 * DO NOT MODIFY THIS FUNCTION
 *
 * data - The pointer to your packet buffer
 * size - The length of your packet
 */
static void dump_packet(unsigned char *data, int size) {
    unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4x",
               ((unsigned int)p-(unsigned int)data) );
        }
            
        c = *p;
        if (isprint(c) == 0) {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0) { 
            /* line completed */
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n%8 == 0) {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0) {
        /* print rest of buffer if not empty */
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}


unsigned int get_number_from_n_chars(char *first_char, int n){
  unsigned char tmp_bytes[4];
  memset(&tmp_bytes, 0, 4);
  memcpy(&tmp_bytes, first_char, n);
  unsigned int val = *tmp_bytes;
  for(int i = 1; i < n; i++){ // start at 1 because first byte is handled
    val = val << 8;
    val |= (*(tmp_bytes + i));
  }
  return val;
}

unsigned int get_int_from_four_chars(char *first){
  return get_number_from_n_chars(first, 4);
}

unsigned short get_short_from_two_chars(char *first){
  return (unsigned short) get_number_from_n_chars(first, 2);
}


/*
 *
 */
int parse_name_at_offset(char *response, int starts_at, char *buff){
  int size_of_next_label = get_number_from_n_chars(response + starts_at, 1);
  int chars_added = 0;
  while(size_of_next_label != 0 && chars_added < 256){
    starts_at++;
    if(size_of_next_label >> 6 == 0x3){
      int pointer = get_number_from_n_chars(response + starts_at -1 , 2);
      pointer &= 0x3fff;
      char pointer_buff[256];
      int added_recursively = parse_name_at_offset(response, pointer, 
                                                   pointer_buff);
      strcpy(buff + chars_added, pointer_buff);
      chars_added += added_recursively;
      break;
    }
    for(int i=0; i < size_of_next_label; i++){
      buff[chars_added] = *(response + starts_at + i);
      chars_added++;
    }
    buff[chars_added] = '.';
    chars_added++;
    starts_at+=size_of_next_label;
    size_of_next_label = get_number_from_n_chars(response + starts_at, 1);
  }
  buff[chars_added-1] = '\0';
  return chars_added;
}

/*
 * buff is the full incoming response. Starts at is the offset into buff where
 * the answer starts. Answer a is the answer we fill in.
 *
 * return the final offset (end of this answer in the buff)
 */
int parse_answer(char *response, int starts_at, answer *a){
  
  int offset = starts_at + 2;  // skipping past the name

  a->type = get_short_from_two_chars(response+offset);
  offset+=2;
  a->class = get_short_from_two_chars(response+offset);
  offset+=2;
  a->ttl = get_int_from_four_chars(response+offset);
  offset+=4;
  a->rdlength = get_short_from_two_chars(response+offset);
  offset+=2;
  if(a->type == 1){
    a->rdata_ip = get_int_from_four_chars(response+offset);
    offset+=4;
  }
  else if (a->type == 5){
    char full_name[256];
    int chars_added = parse_name_at_offset(response, offset, full_name);
    strcpy(a->rdata_cname, full_name);
    offset += chars_added;
  }
  return offset;
}

int convert_to_ip(unsigned int raw_ip, char *buf){
  
  int nums[4];
  for (int i = 0; i < 4; i++){
    int ip = raw_ip;
    ip = ip >> (8 * (3 - i));
    nums[i] = ip % 128;
  }

  sprintf(buf, "%d.%d.%d.%d", nums[0], nums[1], nums[2], nums[3]);

  return 0;
}

int main(int argc, char *argv[]) {
  /**
   * I've included some basic code for opening a socket in C, sending
   * a UDP packet, and then receiving a response (or timeout).  You'll 
   * need to fill in many of the details, but this should be enough to
   * get you started.
   */

  // process the arguments
  char server[22]; // max length of server + port
  strcpy(server, argv[1] + 1); // + 1 is to go past the "@" symbol
  char *ip = strtok(server, ":");
  char *port_alpha = strtok(NULL, ":");
  // if no port is given, set it to 53
  if(port_alpha == NULL)
    port_alpha = "53";
  short port = atoi(port_alpha);
  
  char name[100];
  strcpy(name, argv[2]);
  char *temp;
  char parsedname[64];
  memset(parsedname, 0, sizeof(parsedname));
  temp = strtok(name, ".");
  int len = strlen(temp);
  sprintf(parsedname, "%c%s", len, temp);
  while((temp = strtok(NULL, ".")) != NULL) {
    char str[100];
    len = strlen(temp);
    sprintf(str, "%c%s", len, temp);
    strcat(parsedname, str);
  }
  strcat(parsedname, "\0");

  // construct the DNS request
  header head;
  head.id = htons(1337);
  head.qr = 0;
  head.opcode = 0;
  head.aa = 0;
  head.tc = 0;
  head.rd = 1;
  head.ra = 0;
  head.z = 0;
  head.rcode = 0;
  head.qdcount = htons(1);
  head.ancount = 0;
  head.nscount = 0;
  head.arcount = 0;
  
  /*
  question quest;
  strcpy(quest.qname, parsedname);
  quest.qtype = htons(1);
  quest.qclass = htons(1);
  */
  unsigned short qtype = htons(1);
  unsigned short qclass = htons(1);
  answer ans;
  
  unsigned char packet[1000];
  int offset = sizeof(head);
  memset(packet, 0, sizeof(packet));
  memcpy(packet, &head, sizeof(head));
  memcpy(packet + offset, &parsedname, strlen(parsedname) + 1);
  offset = offset + strlen(parsedname) + 1;
  memcpy(packet + offset, &qtype, sizeof(qtype));
  offset = offset + sizeof(qtype);
  memcpy(packet + offset, &qclass, sizeof(qclass));
  offset = offset + sizeof(qclass);
  //memcpy(packet + sizeof(head), &quest, sizeof(quest));
  //memcpy(packet + sizeof(head) + sizeof(quest), &ans, sizeof(ans));

  // send the DNS request (and call dump_packet with your request)
  dump_packet(packet, offset);
  
  // first, open a UDP socket  
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  // next, construct the destination address
  struct sockaddr_in out;
  out.sin_family = AF_INET;
  out.sin_port = htons(port);
  out.sin_addr.s_addr = inet_addr(ip);

  if (sendto(sock, packet, offset, 0, &out, sizeof(out)) < 0) {
    // an error occurred
    printf("an error occurred\n");
  }

  // wait for the DNS reply (timeout: 5 seconds)
  struct sockaddr_in in;
  socklen_t in_len;

  // construct the socket set
  fd_set socks;
  FD_ZERO(&socks);
  FD_SET(sock, &socks);

  // construct the timeout
  struct timeval t;
  t.tv_sec = 5;
  t.tv_usec = 0;

  int sizeof_recvbuf = 500;
  char *recvbuf = malloc(sizeof_recvbuf * sizeof(char));

  // wait to receive, or for a timeout
  if (select(sock + 1, &socks, NULL, NULL, &t)) {
    if (recvfrom(sock, recvbuf, sizeof_recvbuf, 0, &in, &in_len) < 0) {
      // an error occured
      printf("error in receiving\n");
    }
  } else {
    // a timeout occurred
    printf("timeout occurred\n");
  }

  header response_header;
  int response_offset = 0;

  response_header.id = get_short_from_two_chars(recvbuf);
  response_offset += 2;

  char tmp_byte[1];
  memcpy(&tmp_byte, recvbuf + response_offset, 1);
  response_header.qr = ((*tmp_byte >> 7) & 0x1);
  response_header.opcode = ((*tmp_byte >> 3) & 0xf);
  response_header.aa = ((*tmp_byte >> 2) & 0x1);
  response_header.tc = ((*tmp_byte >> 1) & 0x1);
  response_header.rd = (*tmp_byte & 0x1);
  response_offset++;
  memcpy(&tmp_byte, recvbuf + response_offset, 1);
  response_header.ra = ((*tmp_byte >> 7) & 0x1);
  response_header.z = ((*tmp_byte >> 4) & 0x7);
  response_header.rcode = (*tmp_byte & 0xf);
  response_offset++;

  response_header.qdcount = get_short_from_two_chars(recvbuf + response_offset);
  response_offset+=2;
  response_header.ancount = get_short_from_two_chars(recvbuf + response_offset);
  response_offset+=2;
  response_header.nscount = get_short_from_two_chars(recvbuf + response_offset);
  response_offset+=2;
  response_header.arcount = get_short_from_two_chars(recvbuf + response_offset);
  response_offset+=2;

 
  answer answers[20];
  response_offset = offset; // TODO this is a horrible way to do this
  for(int i = 0; i < response_header.ancount; i++){
    answer a;
    response_offset = parse_answer(recvbuf, response_offset, &a);
    answers[i] = a;
  }

  char *auth = "auth";
  if (response_header.aa == 0)
    auth = "nonauth";
  for(int i = 0; i < response_header.ancount; i++){
    if (answers[i].type == 1){
      char ip_addr[15];
      convert_to_ip(answers[i].rdata_ip, ip_addr);
      printf("IP\t%s\t%s\n", ip_addr, auth);
    }
    else{
      printf("CNAME\t%s\t%s\n", answers[i].rdata_cname, auth);
    }
  }

  // print out the result
  printf("\n");
  dump_packet(recvbuf, sizeof_recvbuf);
 
  return 0;
}
