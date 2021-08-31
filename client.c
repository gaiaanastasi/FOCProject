//CLIENT

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "crypto.c"
#include "utility.c"

const int port_address = 4242;
const char ip_address[16] = "127.0.0.1"
const char welcomeMessage[256] = "Hi! This is a secure messaging system \n Type: \n (1) to see who's online \n (2) to send a request to talk (3) to log out\n\n What do you want to do? ";

int main(){
	int socket;
	unsigned command;			//command tyoed by the user
	char myNonce[DIM_NONCE];	//it will store the nonce created by the client

	//socket creation and instantiation
	socket = socket(AF_INET, SOCK_STREAM, 0);
	memset(&srv_addr, 0, sizeof(srv_addr)); // Pulizia 
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(atoi(port_address));
    inet_pton(AF_INET, ip_address, &srv_addr.sin_addr);
    ret = connect(socket, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
	if(ret < 0){
		perror("An error occured during the connection phase \n");
		exit(-1);
	}

	//authentication with the server
	generateNonce(myNonce);


	printf("%s", welcomeMessage);
	while(1){
		if(scanf("%d", &command) =! 1){
			perror("scanf function has read a wrong number of items \n");
			exit(-1);
		}
		switch(command){
			case 1:		//online people
				break;
			case 2:		//request to talk
				break;
			case 3:		//logging out
				break;

		}
	}

	return 0;
}