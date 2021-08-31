//CLIENT

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/x509.h>
#include "crypto.c"
#include "utility.c"

const int port_address = 4242;
const char ip_address[16] = "127.0.0.1"
const char welcomeMessage[256] = "Hi! This is a secure messaging system \n Type: \n (1) to see who's online \n (2) to send a request to talk (3) to log out\n\n What do you want to do? ";

int main(int argc, const char** argv){
	int socket;
	size_t command;			//command typed by the user
	char* message_recv;
	char* message_send;
	char serverNonce[DIM_NONCE];
	X509* serverCertificate = NULL;
	char* opBuffer; 		//buffer used for different operations
	int dimOpBuffer = 0;	//length of the content of opBuffer	

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
	message_recv = receive_obj(socket, &dimOpBuffer);
	serverNonce = extract_data_from_array(message_recv, 0, DIM_NONCE);
	if(serverNonce == NULL){
		perror("Error during the extraction of the nonce of the server\n");
		exit(-1);
	}
	opBuffer = extract_data_from_array(message_recv, DIM_NONCE, dimOpBuffer);	//opBuffer will contain the serialized certificate of the server
	if(opBuffer == NULL){
		perror("Error during the extraction of the certificate of the server\n");
		exit(-1);
	}
	serverCertificate = d2i_X509(NULL, &opBuffer, dimOpBuffer - DIM_NONCE);
	if(serverCertificate == NULL){
		perror("Error during deserialization of the certificate of the server\n");
		exit(-1);
	}
	
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