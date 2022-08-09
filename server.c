// A simple server in the internet domain using TCP
// The port number is passed as an argument
// To compile: gcc server.c -o server
// Reference: Beej's networking guide, man pages

#define _POSIX_C_SOURCE 200112L
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv) {
	int sockfd, newsockfd, n, re, i, s;
	char buffer[256];
	struct addrinfo hints, *res;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size;

	if (argc < 2) {
		fprintf(stderr, "ERROR, no port provided\n");
		exit(EXIT_FAILURE);
	}

	// Create address we're going to listen on (with given port number)
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;       // IPv4
	hints.ai_socktype = SOCK_STREAM; // TCP
	hints.ai_flags = AI_PASSIVE;     // for bind, listen, accept
	// node (NULL means any interface), service (port), hints, res
	s = getaddrinfo(NULL, argv[1], &hints, &res);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	// Create socket
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	// Reuse port if possible
	re = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	// Bind address to the socket
	if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(res);
    while(1) {
        // Listen on socket - means we're ready to accept connections,
        // incoming connection requests will be queued, man 3 listen
        if (listen(sockfd, 5) < 0) {
            perror("listen");
            exit(EXIT_FAILURE);
        }

        // Accept a connection - blocks until a connection is ready to be accepted
        // Get back a new file descriptor to communicate on
        client_addr_size = sizeof client_addr;
        newsockfd =
            accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_size);
        if (newsockfd < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Read characters from the connection, then process
        while (1) {
            n = read(newsockfd, buffer, 255); // n is number of characters read
            if (n < 0) {
                perror("ERROR reading from socket");
                exit(EXIT_FAILURE);
            }
            // Null-terminate string
            buffer[n] = '\0';

            // Disconnect
            if (n == 0) {
                break;
            }

            // Exit on Goodbye
            if (strncmp(buffer, "GOODBYE-CLOSE-TCP", 17) == 0) {
                close(newsockfd);
                break;
            }

            // Convert to uppercase
            for (i = 0; i < n; i++) {
                buffer[i] = toupper(buffer[i]);
            }

            // A rather ugly solution for the buffer
            char initial[] = "Here is the message in upper: ";
            // Move original text in buffer (with \0) forwards
            memmove(buffer + strlen(initial), buffer, n + 1);
            // Prepend "Here is message in upper: " without \0
            memmove(buffer, initial, strlen(initial));
            printf("%s\n", buffer);
            // strlen only because content of buffer is null-terminated string
            n = write(newsockfd, buffer, strlen(buffer));
            if (n < 0) {
                perror("write");
                exit(EXIT_FAILURE);
            }
        }

        close(newsockfd);
    }
    close(sockfd);
	return 0;
}
