/*
 * CS3600, Fall 2013
 * Project 2 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#ifndef __3600DNS_H__
#define __3600DNS_H__

#endif

typedef struct {
  unsigned short id;
  
  unsigned int rd:1;
  unsigned int tc:1;
  unsigned int aa:1;
  unsigned int opcode:4;
  unsigned int qr:1;
  unsigned int rcode:4;
  unsigned int z:3;
  unsigned int ra:1;
  
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short nscount;
  unsigned short arcount;

} header;

typedef struct {
  char *qname;
  unsigned short qtype;
  unsigned short qclass;
} question;

typedef struct {
  //char name[64];
  unsigned short type;
  unsigned short class;
  unsigned int ttl;
  unsigned short rdlength;
  unsigned int rdata_ip;
  char rdata_cname[256];
  unsigned short mx_preference;
} answer;



