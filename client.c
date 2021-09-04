//CLIENT

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <unistd.h>
#include "crypto.c"

const int port_address = 4242;
const char ip_address[16] = "127.0.0.1";
const char commandMessage[256] = "Type: \n (1) to see who's online \n (2) to send a request to talk \n (3) to wait for a request \n	(4) to log out\n\n What do you want to do? ";

int main(int argc, const char** argv){
	int sock;				//socket identifier
    struct sockaddr_in srv_addr;
	int ret;				//it will contain different integer return values (used for checking)
	size_t command;			//command typed by the user
	unsigned char* message_recv;
	int recv_len = 0;		//length of the received message
	unsigned char* message_send;
	int send_len = 0;		//length of the message to be sent
	unsigned char* ciphertext;		//result of the encryption of the message that has to be sent
	int cpt_len = 0;		//length of the cyphertext
	unsigned char* plaintext;
	int pt_len = 0;			//length of the plaintext
	unsigned char* serverSymmetricKey;
	unsigned char* clientSimmetricKey;
	unsigned char serverNonce[DIM_NONCE];
	unsigned char clientNonce[DIM_NONCE];
	X509* serverCertificate = NULL;
	X509* CACertificate = NULL;
	unsigned char* opBuffer; 		//buffer used for different operations
	int dimOpBuffer = 0;	//length of the content of opBuffer	
	X509_STORE* certStore = NULL;	//certificate store of the client
	EVP_PKEY* serverPubK = NULL;	//public key of the server
	EVP_PKEY* dhPrivateKey = NULL;	//private key generated by DH algorithm
	EVP_PKEY* myPrivK = NULL;		//private key of the user
	EVP_PKEY* myPubK = NULL;		//public key of the user
	EVP_PKEY* DHServerPubK = NULL;	//Diffie-Hellman public key of the server
	char fileName[64];				//it will contain different names for different files
	char username[DIM_USERNAME];		//username to log in
	char password[DIM_PASSWORD];		//password to find the private key
	char* charPointer;				//generic pointer used in different parts
	unsigned char* signature;			//it will contain the signature
	int signatureLen;			//len of the signature
	FILE* file = NULL;			//generic file pointer used in different parts of the code
	fd_set readFdSet;			//fd set that will contain the socket and the stdin, in order to know if a request is arrived or if the user has typed something

	//socket creation and instantiation
	sock = socket(AF_INET, SOCK_STREAM, 0);
	memset(&srv_addr, 0, sizeof(srv_addr)); // Pulizia
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(port_address);
	inet_pton(AF_INET, ip_address, &srv_addr.sin_addr);
    ret = connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
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
		*charPointer = '\0';
	printf("Insert your password:\t");
	if(fgets(password, DIM_PASSWORD, stdin) == NULL){
		perror("Error during the reading from stdin\n");
		exit(-1);
	}
	charPointer = strchr(password, '\n');
	if(charPointer)
		*charPointer = '\0';
	
	//LOADING PRIVATE KEY
	strcpy(fileName, "keys/");
	strcat(fileName, username);
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

	//LOADING PUBLIC KEY
	strcpy(fileName, "keys/");
	strcat(fileName, username);
	strcat(fileName, "_pubkey.pem");
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

	//CERTIFICATE STORE CREATION
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
	ret = X509_STORE_add_cert(certStore, CACertificate);
	if(ret != 1){
		perror("Error during the adding of a certificate\n");
		exit(-1);
	}

	//AUTHENTICATION WITH THE SERVER
	recv_len = receive_len(sock);
	message_recv = (unsigned char*) malloc(recv_len);
	receive_obj(sock, message_recv, recv_len);
	extract_data_from_array(serverNonce, message_recv, 0, DIM_NONCE);
	if(serverNonce == NULL){
		perror("Error during the extraction of the nonce of the server\n");
		exit(-1);
	}
	dimOpBuffer = recv_len - DIM_NONCE;
	opBuffer = (unsigned char*) malloc((dimOpBuffer));
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
	if(!verifyCertificate(certStore, serverCertificate)){
		perror("Error during verification of the server certificate\n");
		exit(-1);
	}

	serverPubK = X509_get_pubkey(serverCertificate);
	if(serverPubK == NULL){
		perror("Error during the extraction of the public key of the server from its certificate\n");
		exit(-1);
	}
	//now that I have the public key of the server, the certificate is useless
	X509_free(serverCertificate);
	free(message_recv);
	recv_len = 0;

	//CREATION OF THE MESSAGE THAT HAS TO BE SENT TO THE SERVER (CLIENT AUTHENTICATION)
	sumControl(DIM_NONCE, DIM_USERNAME);
	dimOpBuffer = DIM_NONCE + DIM_USERNAME;
	opBuffer = (unsigned char*) malloc(dimOpBuffer);
	concat2Elements(opBuffer, serverNonce, username, DIM_NONCE, DIM_USERNAME);
	signature = (unsigned char*)malloc(EVP_PKEY_size(myPrivK));
	signatureFunction(opBuffer, dimOpBuffer, signature, &signatureLen, myPrivK);
	send_len = dimOpBuffer + signatureLen;
	message_send = (unsigned char*) malloc(send_len);
	concat2Elements(message_send, opBuffer, signature, dimOpBuffer, signatureLen);

	send_obj(sock, message_send, send_len);
	free(message_send);
	send_len = 0;

	//SYMMETRIC SESSION KEY NEGOTIATION BY MEANS OF EPHEMERAL DIFFIE-HELLMAN
	
	dhPrivateKey = generateDHParams();
	

	//SERIALIZATION OF THE DH PUBLIC KEY
	opBuffer = serializeDHpublicKey(dhPrivateKey, &dimOpBuffer);
	if(opBuffer == NULL){
		perror("Error during serialization of the DH public key\n");
		exit(-1);
	}
	//opBuffer contains the DH public key

	//CREATION OF THE MESSAGE THAT HAS TO BE SENT TO THE SERVER (DH PUB KEY EXCHANGE)
	sumControl(DIM_NONCE, dimOpBuffer);
	pt_len = DIM_NONCE + dimOpBuffer;
	plaintext = (unsigned char*) malloc(pt_len);
	concat2Elements(plaintext, serverNonce, opBuffer, DIM_NONCE, dimOpBuffer);
	//delete public key from opBuffer
#pragma optimize("", off)
   	memset(opBuffer, 0, dimOpBuffer);
#pragma optimize("", on)
	free(opBuffer);
	dimOpBuffer = 0;

	//asymmetric encryption
	message_send = from_pt_to_DigEnv(plaintext, pt_len, serverPubK, &send_len);
	if(message_send == NULL){
		perror("Error during the asymmetric encryption\n");
		exit(-1);
	}
	// <encrypted_key> | <IV> | <ciphertext>
	send_obj(sock, message_send, send_len);

	//plaintext already freed by from_pt_to_DigEnv()
	free(message_send);
	send_len = 0;

	//RECEIVING DH PUBLIC KEY OF THE SERVER
	recv_len = receive_len(sock);
	message_recv = (unsigned char*) malloc(recv_len);
	receive_obj(sock, message_recv, recv_len);

	//asymmetric decryption
	plaintext = from_DigEnv_to_PlainText(message_recv, recv_len, &pt_len, myPrivK);
	if(plaintext == NULL){
		perror("Error during the asimmetric decryption\n");
		exit(-1);
	}

	//check for the nonce
	dimOpBuffer = DIM_NONCE;
	opBuffer = (unsigned char*) malloc(dimOpBuffer);	//it'll contain the nonce sent in the last message
	extract_data_from_array(opBuffer, plaintext, 0, DIM_NONCE);
	if(memcmp(opBuffer, serverNonce, DIM_NONCE) != 0){
		perror("The two nonces are different\n");
		exit(-1);
	}
	free(opBuffer);
	dimOpBuffer = 0;

	//deserialization of the server DH public key
	dimOpBuffer = pt_len - DIM_NONCE;
	opBuffer = (unsigned char*) malloc(dimOpBuffer);	//it'll contain the serialization of the DH public key of the server
	extract_data_from_array(opBuffer, plaintext, DIM_NONCE, pt_len);
	DHServerPubK = deserializeDHpublicKey(opBuffer, dimOpBuffer);
	if(DHServerPubK == NULL){
		perror("Error during deserialization of the DH public key\n");
		exit(-1);
	}
	serverSymmetricKey = symmetricKeyDerivation_for_aes_128_gcm(dhPrivateKey, DHServerPubK);

	//now that we have a fresh symmetric key, some informations are useless
	EVP_PKEY_free(serverPubK);
	EVP_PKEY_free(DHServerPubK);
	EVP_PKEY_free(dhPrivateKey);
	free(opBuffer);
	dimOpBuffer = 0;
	free(plaintext);
	free(message_recv);
	recv_len = 0;

	printf("Hi! This is a secure messaging system\n");
	while(1){
		printf("%s", commandMessage);
		FD_ZERO(&readFdSet);		//cleaning the set
		FD_SET(0, &readFdSet);		//stdin added to the set
		FD_SET(sock, &readFdSet);		//sock added to the set
		ret = select(sock + 1, &readFdSet, NULL, NULL, NULL);
		if(ret < 0){
			perror("Error during select()\n");
			exit(-1);
		}
		if(FD_ISSET(0, &readFdSet)){
			//the user has typed something
			if(scanf("%1ld", &command) != 1){
				perror("scanf function has read a wrong number of items \n");
				exit(-1);
			}
			while(getchar() != '\n');		//cleaning the stdin buffer
			switch(command){
				case 1:		//online people
					break;
				case 2:		//request to talk
					break;
				case 3:		//logout
					break;
				default:
					perror("The inserted command is not valid\n");
					break;
			}
		}
		else if(FD_ISSET(sock, &readFdSet)){
			//a request to talk has arrived
		}
	}
	EVP_PKEY_free(myPrivK);
	EVP_PKEY_free(myPubK);
	X509_STORE_free(certStore);
	close(sock);
	return 0;
}