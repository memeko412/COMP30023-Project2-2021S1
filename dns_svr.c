// DNS proxy server based off lab 9
// sample answer client-1.2.3.c and
// server-1.2.3.c

#define _POSIX_C_SOURCE 200112L
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "phase1.h"
#define PORTNUMBER 8053


int main(int argc, char** argv) {
    int clisockfd, newclisockfd,serversockfd, n, re, s;
    struct addrinfo hints, *res, serverhints, *servinfo, *rp;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_size;
    // Create address we're going to listen on (with given port number)
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_flags = AI_PASSIVE;     // for bind, listen, accept
    char * port = (char *)malloc(4*sizeof(char));
    sprintf(port, "%d", PORTNUMBER);
    s = getaddrinfo(NULL, port, &hints, &res);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }
    // Create socket
    clisockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (clisockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    // Reuse port if possible
    re = 1;
    if (setsockopt(clisockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    // Bind address to the socket
    if (bind(clisockfd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(res);
    if (argc < 3) {
		fprintf(stderr, "usage %s hostname port\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	// Create address
	memset(&serverhints, 0, sizeof serverhints);
	serverhints.ai_family = AF_INET;
	serverhints.ai_socktype = SOCK_STREAM;
    // Get addrinfo of server. From man page:
	// The getaddrinfo() function combines the functionality provided by the
	// gethostbyname(3) and getservbyname(3) functions into a single interface
	s = getaddrinfo(argv[1], argv[2], &serverhints, &servinfo);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}
    // Connect to first valid result
	// Why are there multiple results? see man page (search 'several reasons')
	// How to search? enter /, then text to search for, press n/N to navigate
	for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
		serversockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (serversockfd == -1)
			continue;

		if (connect(serversockfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break; // success

		close(serversockfd);
	}
	if (rp == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(servinfo);
    while(1) {
        // Listen on socket - means we're ready to accept connections,
        // incoming connection requests will be queued, man 3 listen
        if (listen(clisockfd, 5) < 0) {
            perror("listen");
            exit(EXIT_FAILURE);
        }

        // Accept a connection - blocks until a connection is ready to be accepted
        // Get back a new file descriptor to communicate on
        client_addr_size = sizeof client_addr;
        newclisockfd =
            accept(clisockfd, (struct sockaddr*)&client_addr, &client_addr_size);
        if (newclisockfd < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Read packets from the client
        while (1) {
            printf("Reading packets:\n");
            unsigned char lenbuffer[2];
            n = read(newclisockfd,lenbuffer,2);
            int len = (lenbuffer[0] << 8) | lenbuffer[1];
            unsigned char * clientbuffer = (unsigned char *)malloc(len * sizeof(unsigned char));
            int bytesread = 0;
            while(bytesread < len) {
                n = read(newclisockfd,clientbuffer+bytesread,len-bytesread);
                bytesread += n;
            }
            int client_packet_status;
            client_packet_status = parse_dns_packet(clientbuffer,len);
            // if the request is not of type AAAA, return packet with error code 4
            if (client_packet_status) {
                unsigned char * newbuffer = make_error_packet(clientbuffer,len);
                unsigned char * returnbuffer = combine_packet(lenbuffer,newbuffer,len+2);
                n = write(newclisockfd,returnbuffer,len+2);
                free(returnbuffer);
                free(newbuffer);
                close(newclisockfd);
                break;
            }
            // otherwise, query the name server by passing on the packet from client
            // wait for name server response, parse and pass on the packet to client
            unsigned char * packetbuffer = combine_packet(lenbuffer,clientbuffer,len+2);
            printf("Sending Packets:\n");
            n = write(serversockfd, packetbuffer, len+2);
            free(packetbuffer);
            n = read(serversockfd,lenbuffer,2);
            len = (lenbuffer[0] << 8) | lenbuffer[1];
            unsigned char * serverbuffer = (unsigned char *)malloc(len * sizeof(unsigned char));
            bytesread = 0;
            while (bytesread < len) {
                n = read(serversockfd,serverbuffer+bytesread,len-bytesread);
                bytesread += n;
            }
            parse_dns_packet(serverbuffer,len);
            unsigned char * returnbuffer = combine_packet(lenbuffer,serverbuffer,len+2);
            n = write(newclisockfd,returnbuffer,len+2);
            free(serverbuffer);
            free(returnbuffer);
            printf("Ending connection\n");
            close(newclisockfd);
        }
    }
    return 0;
}

