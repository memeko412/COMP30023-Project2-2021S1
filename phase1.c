
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include "phase1.h"

int parse_dns_packet(unsigned char buffer[], int len);
unsigned char * make_error_packet(unsigned char buffer[],int packetlen);
unsigned char * combine_packet(unsigned char lenbuf[], unsigned char buffer[], int packetlen);

// Combine the packet length buffer with the packet buffer
unsigned char * combine_packet(unsigned char lenbuf[], unsigned char buffer[], int packetlen) {
    unsigned char * combined_packet = (unsigned char *)malloc(packetlen * sizeof(unsigned char));
    for (int i = 0; i < 2; i++) {
        combined_packet[i] = lenbuf[i];
    }
    for (int i = 2; i < packetlen; i++) {
        combined_packet[i] = buffer[i - 2];
    }
    return combined_packet;
}

// Reads a packet and converts rcode to 4
unsigned char * make_error_packet(unsigned char buffer[], int packetlen) {
    unsigned char * newbuffer = (unsigned char *)malloc(packetlen * sizeof(unsigned char));
    //copy the buffer to a new buffer to be returned
    memcpy(newbuffer,buffer, packetlen);
    //change QR to 1
    newbuffer[2] = newbuffer[2] | (1 << 7);
    //change RCODE to 4
    newbuffer[3] = ((newbuffer[3] & 240) | 4);
    return newbuffer;
}

int parse_dns_packet(unsigned char buffer[], int len) {
    FILE *f;
    f = fopen("dns_svr.log","a+");
    for (int i = 0; i < len; i++) {
        printf("%.2x",buffer[i]);
    }
    printf("\n");
    printf("ID: %.2x%.2x\n",buffer[0],buffer[1]);
    printf("Query Parameters: %.2x%.2x\n",buffer[2],buffer[3]);
    int qr = (buffer[2] >> 7 & 1);
    printf("QR is: %d\n",qr);
    int op = ((buffer[2] << 1 >> 4) & 15);
    printf("OP is: %d\n",op);
    if(qr) {
        printf("This is a response.\n");
    } else {
        printf("This is a request.\n");
    }
    int aa = (buffer[2] >> 2 & 1);
    printf("AA is: %d\n",aa);
    int tc = (buffer[2] >> 1 & 1);
    printf("TC is: %d\n",tc);
    int rd = (buffer[2] & 1);
    printf("RD is: %d\n",rd);
    int ra = (buffer[3] >> 7 & 1);
    printf("RA is: %d\n",ra);
    int rc = (buffer[3] & 15);
    printf("RCODE is: %d\n",rc);
    int qd = (buffer[4] << 8 | buffer[5]);
    int an = (buffer[6] << 8 | buffer[7]);
    int ns = (buffer[8] << 8 | buffer[9]);
    int ar = (buffer[10] << 8 | buffer[11]);
    printf("Number of question: %d\n",qd);
    printf("Number of answers: %d\n",an);
    printf("Number of authority records: %d\n",ns);
    printf("Number of additional records %d\n",ar);
    int currentindex = 12;
    int labellen = 0;
    int tempindex = 0;
    time_t t ;
    struct tm *info;
    char timebuffer[20];
    time(&t);
    info = localtime(&t);
    strftime(timebuffer,80,"%FT%T%z",info);
    if(!qr) {
        fprintf(f,"%s requested ",timebuffer);
        fflush(f);
    }
    while(buffer[currentindex] | 00000000) {
        labellen = buffer[currentindex];
        //printf("Length of label is: %d\n",labellen);
        for (int i = currentindex+1; i < currentindex+1+labellen; i++) {
            printf("%c",buffer[i]);
            if(!qr) {
                fprintf(f,"%c",buffer[i]);
                fflush(f);
            }
            tempindex = i;
        }
        currentindex = tempindex+1;
        if(buffer[currentindex] | 00000000) {
            printf(".");
            if(!qr) {
                fprintf(f,".");
                fflush(f);
            }
        }
    }
    printf("\n");
    if(!qr) {
        fprintf(f,"\n");
        fflush(f);
    }
    int type = (buffer[currentindex+1] << 8 | buffer[currentindex+2]);
    printf("Type is: %d\n",type);
    int class = (buffer[currentindex+3] << 8 | buffer[currentindex+4]);
    if(type != 28 && !qr) {
        info = localtime(&t);
        strftime(timebuffer,80,"%FT%T%z",info);
        fprintf(f,"%s unimplemented request\n",timebuffer);
        fflush(f);
        return 1;
    }
    printf("Class is: %d\n",class);
    currentindex += 5;
    printf("---------------End of questions--------------\n");
    if (qr) {
        int printlog = 1;
        printf("Answers: \n");
        int currentanswer = 0;
        while (currentanswer < an) {
            int offset = (buffer[currentindex] << 8 | buffer[currentindex+1])&16383;
            printf("The offset is: %d\n",offset);
            printf("This is the answer to: ");
            tempindex = offset;
            printf("\n");
            currentindex += 2;
            int answertype = (buffer[currentindex] << 8 | buffer[currentindex+1]);
            printf("Answer type is: %d\n",answertype);
            if(currentanswer > 0 || answertype != 28) {
                printlog = 0;
            }
            if(printlog){
                info = localtime(&t);
                strftime(timebuffer,80,"%FT%T%z",info);
                fprintf(f,"%s ",timebuffer);
                fflush(f);
            }
            while(buffer[tempindex] || 00000000) {
                labellen = buffer[tempindex];
                for (int i = tempindex+1;i<tempindex+1+labellen;i++) {
                    printf("%c",buffer[i]);
                    if(printlog) {
                        fprintf(f,"%c",buffer[i]);
                        fflush(f);
                    }
                }
                tempindex = tempindex+1+labellen;
                if(buffer[tempindex] | 00000000) {
                    printf(".");
                    if(printlog) {
                        fprintf(f,".");
                        fflush(f);
                    }
                }
            }
            printf("\n");
            currentindex += 2;
            int answerclass = (buffer[currentindex] << 8 | buffer[currentindex+1]);
            printf("Answer class is: %d\n", answerclass);
            currentindex += 2;
            int ttl = (((buffer[currentindex] << 8 | buffer[currentindex+1]) << 8 | buffer[currentindex+2]) << 8 | buffer[currentindex+3]);
            printf("Answer's time to live is: %d\n",ttl);
            currentindex += 4;
            int rd = (buffer[currentindex] << 8 | buffer[currentindex+1]);
            printf("Answer's rdlength is %d\n", rd);
            currentindex += 2;
            if (answertype == 28) {
               struct in6_addr ip = {{{buffer[currentindex],buffer[currentindex+1],buffer[currentindex+2],buffer[currentindex+3],\
                                       buffer[currentindex+4],buffer[currentindex+5],buffer[currentindex+6],buffer[currentindex+7],\
                                       buffer[currentindex+8],buffer[currentindex+9],buffer[currentindex+10],buffer[currentindex+11],\
                                       buffer[currentindex+12],buffer[currentindex+13],buffer[currentindex+14],buffer[currentindex+15]}}};
               char addr[INET6_ADDRSTRLEN];
               inet_ntop(AF_INET6,&ip,addr,INET6_ADDRSTRLEN);
               printf("Address%d is:\n%s\n",currentanswer+1,addr);
               if(printlog) {
                  fprintf(f," is at %s\n",addr);
                  fflush(f);
               }
            }
            currentindex += rd;
            currentanswer ++;
        }
    }
    fclose(f);
    return 0;
}





