#ifndef PHASE1_H_INCLUDED
#define PHASE1_H_INCLUDED

int parse_dns_packet(unsigned char buffer[], int len);
unsigned char * make_error_packet(unsigned char buffer[],int packetlen);
unsigned char * combine_packet(unsigned char lenbuf[], unsigned char buffer[], int packetlen);
#endif

