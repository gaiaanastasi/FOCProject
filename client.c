//CLIENT

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "crypto.c"
#include "utility.c"

const int port_address = 4242;
const char ip_address[16] = "127.0.0.1"
const char welcomeMessage[256] = "Hi! This is a secure messaging system \n Type: \n (1) to see who's online \n (2) to send a request to talk (3) to log out\n\n What do you want to do? ";
const int DIM_USERNAME = 32;
const int DIM_PASSWORD = 32;

int main(int argc, const char** argv){
	int socket;
	int ret;				//it will contain different integer return values (used for checking)
	size_t command;			//command typed by the user
	char* message_recv;
	int recv_len = 0;		//length of the received message
	char* message_send;
	int send_len = 0;		//length of the message to be sent
	char serverNonce[DIM_NONCE];
	X509* serverCertificate = NULL;
	X509* CACertificate = NULL;
	char* opBuffer; 		//buffer used for different operations
	int dimOpBuffer = 0;	//length of the content of opBuffer	
	X509_STORE* certStore = NULL;	//certificate store of the client
	X509_STORE_CTX* storeCtx = NULL;	//context for certificate verification
	EVP_PKEY* serverPubK = NULL;	//public key of the server
	EVP_PKEY* dhPrivateKey = NULL;	//private key generated by DH algorithm
	EVP_PKEY* myPrivK = NULL;		//private key of the user
	EVP_PKEY* myPubK = NULL;		//public key of the user
	char fileName[64];				//it will contain different names for different files
	char username[DIM_USERNAME];		//username to log in
	char password[DIM_PASSWORD];		//password to find the private key
	char* charPointer;				//generic pointer used in different parts
	char* signature;			//it will contain the signature
	int signatureLen;			//len of the signature
	FILE* file = NULL;			//generic file pointer used in different parts of the code

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

	//log in of the user
	memset(username, 0, DIM_USERNAME);
	printf("Insert your username:\t");
	if(fgets(username, DIM_USERNAME, stdin) == NULL){
		perror("Error during the reading from stdin\n");
		exit(-1);
	}
	charPointer = strchr(username, '\n');
	if(charPointer)
		*p = '\0';
	printf("Insert your password:\t");
	if(fgets(password, DIM_PASSWORD, stdin) == NULL){
		perror("Error during the reading from stdin\n");
		exit(-1);
	}
	charPointer = strchr(password, '\n');
	if(charPointer)
		*p = '\0';
	
	//loading private key
	strcpy(fileName, username);
	strcat(fileName, "_privkey.pem");
	file = fopen(fileName, "r");
	if(file == NULL){
		perror("Error during the opening of a file\n");
		exit(-1);
	}
	myPrivK = PEM_read_PrivateKey(file, NULL, NULL, password);
	if(myPrivK == NULL){
		perror("Error during the loading of the private key, maybe wrong password?\n");
		exit(-1);
	}
	fclose(file);

	//loading public key
	strcpy(fileName, username);
	strcat(fileName, "pubkey.pem");
	file = fopen(fileName, "r");
	if(file == NULL){
		perror("Error during the opening of a file\n");
		exit(-1);
	}
	myPubK = PEM_read_PUBKEY(file, NULL, NULL, NULL);
	if(myPubK == NULL){
		perror("Error during the loading of the public key\n");
		exit(-1);
	}
	fclose(file);

	//certificate store creation
	strcpy(fileName, "certificates/CA_cert.pem");
	file = fopen(fileName, "r");
	if(file == NULL){
		perror("Error during opening of the file CA_cert.pem\n");
		exit(-1);
	}
	CACertificate = PEM_read_X509(file, NULL, NULL, NULL);
	fclose(file);
	if(CACertificate == NULL){
		perror("Error during the extraction of the certificate from the file\n");
		exit(-1);
	}
	certStore = X509_STORE_new();
	if(certStore == NULL){
		perror("Error during the creation of the store\n");
		exit(-1);
	}
	ret = x509_STORE_add_cert(certStore, CACertificate);
	if(ret != 1){
		perror("Error during the adding of a certificate\n");
		exit(-1);
	}

	//authentication with the server
	recv_len = receive_len(socket);
	message_recv = (char*) malloc(recv_len * sizeof(char));
	receive_obj(socket, message_recv, recv_len);
	serverNonce = (char*) malloc((DIM_NONCE) * sizeof(char));
	extract_data_from_array(serverNonce, message_recv, 0, DIM_NONCE);
	if(serverNonce == NULL){
		perror("Error during the extraction of the nonce of the server\n");
		exit(-1);
	}
	dimOpBuffer = recv_len - DIM_NONCE;
	opBuffer = (char*) malloc((dimOpBuffer) * sizeof(char));
	extract_data_from_array(opBuffer, message_recv, DIM_NONCE, recv_len);	//opBuffer will contain the serialized certificate of the server
	if(opBuffer == NULL){
		perror("Error during the extraction of the certificate of the server\n");
		exit(-1);
	}
	serverCertificate = d2i_X509(NULL, (const unsigned char**)&opBuffer, dimOpBuffer);
	if(serverCertificate == NULL){
		perror("Error during deserialization of the certificate of the server\n");
		exit(-1);
	}

	//now that I have the certificate, its serialization is useless
	free(opBuffer);
	dimOpBuffer = 0;
	//certificate verification
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
	//now that I have the public key of the server, the certificate is useless
	X509_free(serverCertificate);
	free(message_recv);
	recv_len = 0;

	//creation of the message that has to be sent to the server (client authentication)
	dimOpBuffer = DIM_NONCE + DIM_USERNAME;
	opBuffer = (char*) malloc(dimOpBuffer * sizeof(char));
	memcpy(opBuffer, serverNonce, DIM_NONCE);
	memcpy(opBuffer + DIM_NONCE, username, DIM_USERNAME);
	signature = (char*)malloc(EVP_PKEY_size(myPrivK));
	signatureFunction(opBuffer, dimOpBuffer, signature, &signatureLen, myPrivK);
	send_len = dimOpBuffer + signatureLen;
	message_send = (char*) malloc(send_len);
	memcpy(message_send, opBuffer, dimOpBuffer);
	memcpy(message_send + opBuffer, signature, signatureLen);

	send_obj(socket, message_send, send_len);
	free(message_send);
	send_len = 0;

	//symmetric session key negotiation by means of Ephemeral Diffie-Helman
	generateDHPrivateKey(dhPrivateKey);

	//now that we have a symmetric key, some informations are useless
	EVP_PKEY_free(serverPubK);
	free(serverNonce);

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
	EVP_PKEY_free(myPrivK);
	X509_STORE_free(certStore);
	return 0;
}