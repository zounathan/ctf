#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define BUFF_LEN 1024

int main(int argc, char **argv)
{
    int sock, port, err;
    struct sockaddr_in server;
    char buffer[BUFF_LEN];

    // check arguments
    if (argc < 2) {
        fprintf(stderr, "usage: %s port\n", argv[0]);
        exit(1);
    }

    port = atoi(argv[1]);

    // create socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock<0) {
        perror(argv[0]);
        exit(1);
    }

    // bind to the specified port
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port);
  
    err = bind(sock, (struct sockaddr *) &server, sizeof(server));
    if (err<0) {
        perror(argv[0]);
        exit(1);
    }

    fprintf(stderr, "%s: listening on port UDP %d\n", argv[0], port);

    // receive data loop
    while (1) {
    
        memset(buffer, 0, BUFF_LEN);

        // receive data
        err = recvfrom(sock, buffer, BUFF_LEN, 0, NULL, 0);
        if (err<0) {
            perror(argv[0]);
            continue;
        }
      
        // print received data
        fwrite(buffer, err, 1, stdout); 
	    fflush(stdout);

    }

    return 0;

}
