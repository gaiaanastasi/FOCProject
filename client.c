//CLIENT

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include "crypto.c"
#include "utility.c"

const int port_address = 4242;
const char ip_address[16] = "127.0.0.1"
const char welcomeMessage[256] = "Hi! This is a secure messaging system \n Type: \n (1) to see who's online \n (2) to send a request to talk (3) to log out\n\n What do you want to do? ";

int main(int argc, const char** argv){
	int socket;
	int ret;				//it will contain different integer return values (used for checking)
	size_t command;			//command typed by the user
	char* message_recv;
	char* message_send;
	char serverNonce[DIM_NONCE];
	X509* serverCertificate = NULL;
	char* opBuffer; 		//buffer used for different operations
	int dimOpBuffer = 0;	//length of the content of opBuffer	
	X509_STORE* certStore = NULL;	//certificate store of the client
	X509_STORE_CTX* storeCtx = NULL;	//context for certificate verification
	EVP_PKEY* serverPubK = NULL;	//public key of the server

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
	certStore = X509_STORE_new();
	if(certStore == NULL){
		perror("Error during the creation of the store\n");
		exit(-1);
	}
	ret = x509_STORE_add_cert(certStore, serverCertificate);
	if(ret != 1){
		perror("Error during the adding of a certificate\n");
		exit(-1);
	}
	storeCtx = X509_STORE_CTX_new();
	if(storeCtx == NULL){
		perror("Error during the creation of the context for certificate verification\n");
		exit(-1);
	}
	ret = X509_STORE_CTX_init(storeCtx, certStore, serverCertificate, NULL);
	if(ret != 1){
		perror("Error during the initilization of the certificate-verification context");
		exit(-1);
	}
	ret = X509_verify_cert(storeCtx);
	if(ret != 1){
		perror("The certificate of the server can not be verified\n");
		exit(-1);
	}
	//now that I verified the certificate, I can deallocate the certificate-verification context
	X509_STORE_CTX_free(storeCtx);
	serverPubK = X509_get_pubkey(serverCertificate);
	if(serverPubK == NULL){
		perror("Error during the extraction of the public key of the server from the certificate\n");
		exit(-1);
	}

	//symmetric session key negotiation by using Ephemeral Diffie-Helman
	

	//now that we have a symmetric key, the public key of the server is useless
	EVP_PKEY_free(serverPubK);

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
	X509_STORE_free(certStore);
	return 0;
}