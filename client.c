//CLIENT

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <unistd.h>
#include "crypto.c"

#define DIM_SUFFIX_FILE_PUBKEY 12
#define DIM_SUFFIX_FILE_PRIVKEY 13
#define DIM_PASSWORD 32
#define DIR_SIZE 6

const int port_address = 4242;
const char ip_address[16] = "127.0.0.1";
const char commandMessage[256] = "Type: \n (1) to see who's online \n (2) to send a request to talk \n (3) to wait for a request \n	(4) to log out\n\n What do you want to do? ";

//Function that control the communication with another client. If requestingClient is true, it means that the client that called the function
//has requested the communication and so it has to start it by generating and sending the nonce. If it is false, it has to wait the nonce itself 
void communication_with_other_client(int sock, unsigned char* serializedPubKey, int keyLen, EVP_PKEY* myPrivK, bool requestingClient){
	unsigned char clientNonce[DIM_NONCE];		//fresh nonce used for communication with the other client
	EVP_PKEY* clientPubK;						//Public key of the client with wich I want to talk
	EVP_PKEY* dhPrivateKey;			//Diffie-Hellman private key
	EVP_PKEY* dhClientPubK;			//Diffie-Hellman public key sent by the other client
	unsigned char* opBuffer; 		//buffer used for different operations
	int dimOpBuffer = 0;			//length of the content of opBuffer	
	unsigned char* plaintext;
	int pt_len;						//length of the plaintext
	unsigned char* ciphertext;		//result of the encryption of the message that has to be sent
	int cpt_len = 0;				//length of the cyphertext
	unsigned char* simKey;			//simmetric key
	unsigned char* charPointer;

	clientPubK = deserializePublicKey(serializedPubKey, keyLen);
	if(clientPubK == NULL){
		perror("Error during deserialization of the publi key");
		exit(-1);
	}
	if(requestingClient){
		generateNonce(clientNonce);
		send_obj(sock, clientNonce, DIM_NONCE);
	}
	else{
		receive_obj(sock, clientNonce, DIM_NONCE);
	}
	dhPrivateKey = generateDHParams();
	opBuffer = serializePublicKey(dhPrivateKey, &dimOpBuffer);
	concat2Elements(plaintext, clientNonce, opBuffer, DIM_NONCE, dimOpBuffer);
	free(opBuffer);
	dimOpBuffer = 0;
	opBuffer = from_pt_to_DigEnv(plaintext, pt_len, clientPubK, &dimOpBuffer);
	if(opBuffer == NULL){
		perror("Error during asymmetric encryption");
		exit(-1);
	}
	//I send a message { <nonce> | <serializedDHPublicKey> } encrypted by means of the client public key
	send_obj(sock, opBuffer, dimOpBuffer);
	free(plaintext);
	pt_len = 0;
	free(opBuffer);
	dimOpBuffer = receive_len(sock);
	opBuffer = (unsigned char*) malloc(dimOpBuffer);
	receive_obj(sock, opBuffer, dimOpBuffer);
	//I received a message { <nonce> | <serializedDHPublicKey> } encrypted by means of my public key
	plaintext = from_DigEnv_to_PlainText(opBuffer, dimOpBuffer, &pt_len, myPrivK);
	if(plaintext == NULL){
		perror("Error during the asymmetric decription");
		exit(-1);
	}
	free(opBuffer);
	dimOpBuffer = DIM_NONCE;
	opBuffer = (unsigned char*) malloc(dimOpBuffer);
	extract_data_from_array(opBuffer, plaintext, 0, DIM_NONCE);
	if(memcmp(opBuffer, clientNonce, DIM_NONCE) != 0){
		perror("The two nonces are not equal");
		exit(-1);
	}
	free(opBuffer);
	dimOpBuffer = pt_len - DIM_NONCE;
	opBuffer = (unsigned char*) malloc(dimOpBuffer);
	extract_data_from_array(opBuffer, plaintext, DIM_NONCE, pt_len);
	dhClientPubK = deserializePublicKey(opBuffer, dimOpBuffer);
	if(dhClientPubK == NULL){
		perror("Error occured by deserializing the DH public key");
		exit(-1);
	}
	simKey = symmetricKeyDerivation_for_aes_128_gcm(myPrivK, dhClientPubK);
	if(simKey == NULL){
		perror("Error during the generation of the shared simmetric key");
		exit(-1);
	}
	free(opBuffer);
	free(plaintext);
	pt_len = dimOpBuffer = 0;

	//USO I SET PER FARE CONVERSAZIONE BELLA???!?

	if(requestingClient){
		printf("Now you can start the conversation by writing your message!\n");
		if(fgets(opBuffer, 256, stdin) == NULL){
			perror("Error during the reading from stdin\n");
			exit(-1);
		}
		charPointer = strchr(opBuffer, '\n');
		if(charPointer)
			*charPointer = '\0';
	}
}

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
	unsigned char serverNonce[DIM_NONCE];		//fresh nonce used for communication with the server
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
	getPassword(password);
	/*if(fgets(password, DIM_PASSWORD, stdin) == NULL){
		perror("Error during the reading from stdin\n");
		exit(-1);
	}
	charPointer = strchr(password, '\n');
	if(charPointer)
		*charPointer = '\0';*/
	
	printf("\nRequest sended\n");
	
	
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

	
	
	//LOADING PRIVATE KEY
	int lim = DIR_SIZE;//-1;
	strncpy(fileName, "keys/", lim );
	lim = DIM_USERNAME;//-1;
	strncat(fileName, username, lim );
	lim = DIM_SUFFIX_FILE_PRIVKEY;//-1;
	strncat(fileName, "_privkey.pem", lim);
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
	
	

	/*//LOADING PUBLIC KEY
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
	
	*/

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
	//RECEIVING THE NONCE AND THE CERTIFICATE
	recv_len = receive_len(sock);
	message_recv = (unsigned char*) malloc(recv_len);
	if(!recv_len){
		perror("Error during the adding of a certificate\n");
		exit(-1);
	}
	receive_obj(sock, message_recv, recv_len);
	extract_data_from_array(serverNonce, message_recv, 0, DIM_NONCE);
	if(serverNonce == NULL){
		perror("Error during the extraction of the nonce of the server\n");
		exit(-1);
	}
	
	dimOpBuffer = recv_len - DIM_NONCE;
	opBuffer = (unsigned char*) malloc((dimOpBuffer));
	if(!opBuffer){
		perror("malloc");
		exit(-1);
	}
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
	//OPENSSL_free(opBuffer); //DA RIVEDERE
	//free(opBuffer);
	dimOpBuffer = 0;
	
	//CERTIFICATE VERIFICATION
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
	/*dimOpBuffer = DIM_NONCE; 
	unsigned char* opBuffer2 = (unsigned char*) malloc(dimOpBuffer);
	if(!opBuffer2){
		perror("malloc");
		exit(-1);
	}
	memset(opBuffer2, 0, dimOpBuffer);
	memcpy(opBuffer2, serverNonce, dimOpBuffer);*/
	//concat2Elements(opBuffer2, serverNonce, username, DIM_NONCE, DIM_USERNAME);
	signature = (unsigned char*)malloc(EVP_PKEY_size(myPrivK));
	if(!signature){
		perror("malloc");
		exit(-1);
	}
	signatureFunction(serverNonce, DIM_NONCE, signature, &signatureLen, myPrivK);
	sumControl(dimOpBuffer, signatureLen);
	unsigned char* buf = (unsigned char*) malloc(DIM_NONCE+signatureLen);
	if(!buf){
		perror("malloc");
		exit(-1);
	}
	concat2Elements(buf, serverNonce, signature, DIM_NONCE, signatureLen);
	//sumControl(DIM_USERNAME, dimOpBuffer);
	sumControl(DIM_USERNAME, signatureLen+DIM_NONCE);
	send_len = DIM_USERNAME +  signatureLen + DIM_NONCE;
	message_send = (unsigned char*) malloc(send_len);
	if(!message_send){
		perror("malloc");
		exit(-1);
	}
	concat2Elements(message_send, username, buf, DIM_USERNAME, signatureLen+DIM_NONCE);
	

	send_obj(sock, message_send, send_len);
	free(message_send);
	free(buf);
	free(signature);
	send_len = 0;
	signatureLen = 0;

	
	
	int len_status = receive_len(sock);
	unsigned char* status = (unsigned char*) malloc(len_status);
	if(!status){
		perror("malloc");
		exit(-1);
	}
	receive_obj(sock, status, len_status);
	if (strcmp(status, "OK")==0){
		printf("Authentication succeded\n");
	}
	else {
		printf("Authentication failed\n");
		exit(-1);
	}
	free(status);
	/*//SYMMETRIC SESSION KEY NEGOTIATION BY MEANS OF EPHEMERAL DIFFIE-HELLMAN
	
	dhPrivateKey = generateDHParams();
	

	//SERIALIZATION OF THE DH PUBLIC KEY
	opBuffer = serializePublicKey(dhPrivateKey, &dimOpBuffer);
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
	DHServerPubK = deserializePublicKey(opBuffer, dimOpBuffer);
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
					send_len = strlen("online_people") + 1;
					message_send = (unsigned char*) malloc(send_len);
					strcpy(message_send, "online_people");
					send_obj(sock, message_send, send_len);
					recv_len = receive_len(sock);
					message_recv = (unsigned char*) malloc(recv_len);
					receive_obj(sock, message_recv, recv_len);
					printf("%s", message_recv);
					free(message_recv);
					free(message_send);
					send_len = 0;
					recv_len = 0;
					break;
				case 2:		//request to talk
					printf("who do you want to send the request to?\n");
					opBuffer = (unsigned char*) malloc(DIM_USERNAME);
					fgets(opBuffer, DIM_USERNAME, stdin);
					charPointer = strchr(opBuffer, '\n');
					if(charPointer)
						*charPointer = '\0';
					sumControl(DIM_USERNAME, strlen("request") + 1);
					pt_len = DIM_USERNAME + strlen("request") + 1;
					plaintext = (unsigned char*) malloc(pt_len);
					concat2Elements(plaintext, opBuffer, "request", DIM_USERNAME, strlen("request") + 1);
					message_send = symmetricEncryption(plaintext, pt_len, serverSymmetricKey, &send_len);
					send_obj(sock, message_send, send_len);
					send_len = 0;
					free(message_send);
					#pragma optimize("", off);
						memset(plaintext, 0, pt_len);
					#pragma optimize("", on);
					free(plaintext);
					pt_len = 0;
					recv_len = receive_len(sock);
					message_recv = (unsigned char*) malloc(recv_len);
					receive_obj(sock, message_recv, recv_len);
					plaintext = symmetricDecription(message_recv, recv_len, &pt_len, serverSymmetricKey);
					if(strcmp(plaintext, "refused") == 0){
						printf("Your request to talk with %s has been refused\n", opBuffer);
						free(opBuffer);
						dimOpBuffer = 0;
						break;
					}

					//request accepted, the plaintext is the public key of the client
					free(opBuffer);
					dimOpBuffer = 0;
					communication_with_other_client(sock, plaintext, myPrivK);
					free(plaintext);
					pt_len = 0;
					


					break;
				case 3:		//logout
					printf("Logging out\n");
					break;
				default:
					perror("The inserted command is not valid\n");
					break;
			}
		}
		else if(FD_ISSET(sock, &readFdSet)){
			//a request to talk has arrived
			recv_len = receive_len(sock);
			message_recv = (unsigned char*) malloc(recv_len);
			receive_obj(sock, message_recv, recv_len);
			//the message is encrypted by means of the symmetric key used by server and client
			
		}
	}*/
	EVP_PKEY_free(myPrivK);
	EVP_PKEY_free(myPubK);
	X509_STORE_free(certStore);
	
	
	close(sock);
	return 0;
}
