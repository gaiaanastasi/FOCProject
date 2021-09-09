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

const int port_address = 4242;
const char ip_address[16] = "127.0.0.1";
const int MAX_LEN_MESSAGE = 256;
const char commandMessage[MAX_LEN_MESSAGE] = "Type: \n (1) to see who's online \n (2) to send a request to talk \n (3) to wait for a request \n	(4) to log out\n\n What do you want to do? ";


//Function that control the communication with another client. If requestingClient is true, it means that the client that called the function
//has requested the communication and so it has to start it by generating and sending the nonce. If it is false, it has to wait the nonce itself.
//It returns true if the user wanted to leave the conversation, false otherwise
bool communication_with_other_client(int sock, unsigned char* serializedPubKey, int keyLen, EVP_PKEY* myPrivK, bool requestingClient, char* clientUsername, unsigned char* serverSimKey){
	unsigned char clientNonce[DIM_NONCE];		//fresh nonce used for communication with the other client
	EVP_PKEY* clientPubK;						//Public key of the client with wich I want to talk
	EVP_PKEY* dhPrivateKey;			//Diffie-Hellman private key
	EVP_PKEY* dhClientPubK;			//Diffie-Hellman public key sent by the other client
	unsigned char* opBuffer; 		//buffer used for different operations
	int dimOpBuffer = 0;			//length of the content of opBuffer	
	unsigned char* plaintext;
	int pt_len;						//length of the plaintext
	unsigned char* message;	//message that has to be sent
	int msg_len = 0;				//length of the message to be sent
	unsigned char* simKey;			//simmetric key used by the two clients
	unsigned char* charPointer;		//generic char pointer 
	fd_set readSet;					//fd set that will contain the socket and the stdin, in order to know if a request is arrived or if the user has typed something

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
		receive_len(sock);
		receive_obj(sock, clientNonce, DIM_NONCE);
	}
	dhPrivateKey = generateDHParams();
	opBuffer = serializePublicKey(dhPrivateKey, &dimOpBuffer);
	if(opBuffer == NULL){
		perror("Error during the serialization of the key");
		exit(-1);
	}
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
	if(opBuffer == NULL){
		perror("Error during malloc()");
		exit(-1);
	}
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
	if(opBuffer == NULL){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(opBuffer, plaintext, 0, DIM_NONCE);
	if(memcmp(opBuffer, clientNonce, DIM_NONCE) != 0){
		perror("The two nonces are not equal");
		exit(-1);
	}
	free(opBuffer);
	dimOpBuffer = pt_len - DIM_NONCE;
	opBuffer = (unsigned char*) malloc(dimOpBuffer);
	if(opBuffer == NULL){
		perror("Error during malloc()");
		exit(-1);
	}
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

	printf("Now you are ready to talk with %s. You can leave the conversation whenever you want by logging you out by typing '<exit>'\n", clientUsername);

	//the user can both wait for a new message or type its own message to send it to the other user
	while(1){
		FD_ZERO(&readSet);		//cleaning the set
		FD_SET(0, &readSet);		//stdin added to the set
		FD_SET(sock, &readSet);		//sock added to the set
		int ret = select(sock + 1, &readSet, NULL, NULL, NULL);
		if(ret < 0){
			perror("Error during select()\n");
			exit(-1);
		}
		if(FD_ISSET(0, &readSet)){
			//the user has typed something
			pt_len = MAX_LEN_MESSAGE;
			plaintext = (unsigned char*) malloc(pt_len);
			if(plaintext == NULL){
				perror("Error during malloc()");
				exit(-1);
			}
			if(fgets(plaintext, MAX_LEN_MESSAGE, stdin) == NULL){
				perror("Error during the input of the message");
				exit(-1);
			}
			charPointer = strchr(plaintext, '\n');
			if(charPointer)
				*charPointer = '\0';

			//control if the user want to leave the conversation
			if(strcmp(plaintext, "<exit>") == 0){
				//the first time I send the message to the other client, to notify him that I'm leaving the chat
				pt_len = strlen("<exit>") + 1;
				message = symmetricEncryption(plaintext, pt_len, simKey, &msg_len);
				if(message == NULL){
					perror("Error during encryption of the message");
					exit(-1);
				}
				send_obj(sock, message, msg_len);
				free(message);
				msg_len = 0;

				//The second time I send the message to the server, to notify my log-off
				message = symmetricEncryption(plaintext, pt_len, serverSimKey, &msg_len);
				if(message == NULL){
					perror("Error during encryption of the message");
					exit(-1);
				}
				send_obj(sock, message, msg_len);
				free(message);
				free(plaintext);
				return true;
			}

			//encryption and sending of the message
			pt_len = strlen(plaintext) + 1;
			message = symmetricEncryption(plaintext, pt_len, simKey, &msg_len);
			if(message == NULL){
				perror("Error during the encryption of the message");
				exit(-1);
			}
			send_obj(sock, message, msg_len);
			printf("\nmessage sent");
			free(message);
			free(plaintext);
			msg_len = 0;
			pt_len = 0;
		} 
		else if(FD_ISSET(sock, &readSet)){
			//the user received a new message
			msg_len = receive_len(sock);
			message = (unsigned char*) malloc(msg_len);
			if(message == NULL){
				perror("Error during malloc()");
				exit(-1);
			}
			receive_obj(sock, message, msg_len);
			/*
			//we have to check if the message has been sent by the server. In such a case, the plaintext would be "<exit>"
			//and it means that the other client has logged off
			plaintext = symmetricDecription(message, msg_len, &pt_len, serverSimKey);
			if(plaintext == NULL){
				perror("Error during the decription of the message");
				exit(-1);
			}
			if(strcmp(plaintext, "<exit>") == 0){
				printf("\n%s has logged off\n", clientUsername);
				free(plaintext);
				free(message);
				return false;
			}
			free(plaintext);
			*/
			plaintext = symmetricDecription(message, msg_len, &pt_len, simKey);
			if(plaintext == NULL){
				perror("Error during the decription of the message");
				exit(-1);
			}
			if(pt_len > MAX_LEN_MESSAGE){
				perror("The received message is too long");
				exit(-1);
			}
			//control if the other client has logged off
			if(strcmp(plaintext, "<exit>") == 0){
				printf("\n%s has logged off\n", clientUsername);
				free(plaintext);
				free(message)
				break;
			}
			printf("\n");
			printf("%s: ", clientUsername);
			printf("%s\n", plaintext);
			free(plaintext);
			free(message);
			pt_len = msg_len = 0;
		}
	}
	EVP_PKEY_free(clientPubK);
	EVP_PKEY_free(dhPrivateKey);
	EVP_PKEY_free(dhClientPubK);
	free(simKey);
	return false;
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
	unsigned char* plaintext;
	int pt_len = 0;			//length of the plaintext
	unsigned char* serverSymmetricKey;
	unsigned char* clientSimmetricKey;
	unsigned char serverNonce[DIM_NONCE];		//fresh nonce used for communication with the server
	unsigned char myNonce[DIM_NONCE];
	X509* serverCertificate = NULL;
	X509* CACertificate = NULL;
	unsigned char* opBuffer; 		//buffer used for different operations
	int dimOpBuffer = 0;	//length of the content of opBuffer	
	X509_STORE* certStore = NULL;	//certificate store of the client
	EVP_PKEY* serverPubK = NULL;	//public key of the server
	//EVP_PKEY* dhPrivateKey = NULL;	//private key generated by DH algorithm
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
	int continueWhile = 1;		//it remains equal to 1 until the user decide to log out 

	
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
	strncpy(fileName, "keys/", DIR_SIZE);
	strncat(fileName, username, DIM_USERNAME);
	strncat(fileName, "_privkey.pem", DIM_SUFFIX_FILE_PRIVKEY);
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
	
	
	/*
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
	*/
	

	//CERTIFICATE STORE CREATION
	strncpy(fileName, "certificates/CA_cert.pem", strlen("certificates/CA_cert.pem""certificates/CA_cert.pem")+1);
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
	if(!message_recv){
		perror("malloc");
		exit(-1);
	}
	//MESSAGE STRUCTURE: <serverNonce> | <certificate> 
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
	charPointer = opBuffer;
	serverCertificate = d2i_X509(NULL, (const unsigned char**)&charPointer, dimOpBuffer);
	
	if(serverCertificate == NULL){
		perror("Error during deserialization of the certificate of the server\n");
		exit(-1);
	}

	//now that I have the certificate, its serialization is useless
	//OPENSSL_free(opBuffer); //DA RIVEDERE
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
	signature = (unsigned char*) malloc(EVP_PKEY_size(myPrivK));
	if(signature == NULL){
		perror("Error during malloc()");
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
	sumControl (send_len, DIM_NONCE);
	send_len +=DIM_NONCE;
	message_send = (unsigned char*) malloc(send_len);
	if(!message_send){
		perror("malloc");
		exit(-1);
	}
	generateNonce(myNonce);
	// MESSAGE STRUCTURE: <clientNonce> | <username>| {<serverNonce>}signature
	memcpy(message_send, myNonce, DIM_NONCE);
	concatElements(message_send, username,DIM_NONCE, DIM_USERNAME);
	int lim = DIM_NONCE + DIM_USERNAME;
	concatElements(message_send, serverNonce, lim, DIM_NONCE);
	lim += DIM_NONCE;
	concatElements(message_send, signature, lim, signatureLen);
	send_obj(sock, message_send, send_len);
	free(message_send);
	free(signature);
	free(buf);
	send_len = 0;
	signatureLen = 0;
	dimOpBuffer =0;
	lim=0;

	//CLIENT RECEIVES THE STATUS OF ITS AUTHENTICATION WITH SERVER
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
	//SYMMETRIC SESSION KEY NEGOTIATION BY MEANS OF EPHEMERAL DIFFIE-HELLMAN
	//CRYPTO_cleanup_all_ex_data();
	EVP_PKEY* dhPrivateKey = generateDHParams();
	//SERIALIZATION OF THE DH PUBLIC KEY
	opBuffer = serializePublicKey(dhPrivateKey, &dimOpBuffer);
	if(opBuffer == NULL){
		perror("Error during serialization of the DH public key\n");
		exit(-1);
	}
	//opBuffer contains the serialized DH public key

	//DA QUI INIZIAVA COMMENTO


	//CREATION OF THE MESSAGE THAT HAS TO BE SENT TO THE SERVER (DH PUB KEY EXCHANGE)
	sumControl (DIM_NONCE, DIM_NONCE);
	lim = DIM_NONCE+DIM_NONCE;
	sumControl(lim, dimOpBuffer);
	lim += dimOpBuffer;
	buf = (unsigned char*) malloc(lim);
	/*sumControl(lim, DIM_NONCE);
	pt_len = lim + DIM_NONCE;
	plaintext = (unsigned char*) malloc(pt_len);*/
	//MESSAGE STRUCTURE: <clientNonce> | <serverNonce> | <pubkeyDH>
	concatElements(buf, myNonce, 0, DIM_NONCE);
	concatElements(buf, serverNonce, DIM_NONCE, DIM_NONCE);
	concatElements(buf, opBuffer, DIM_NONCE + DIM_NONCE, dimOpBuffer);
	/*subControlInt(pt_len,DIM_NONCE);
	concat2Elements(plaintext, myNonce, buf, DIM_NONCE, lim);*/
	//printf("Messaggio generato e pronto per essere inviato \n");
	
	

	//asymmetric encryption
	message_send = from_pt_to_DigEnv(buf, lim, serverPubK, &send_len);
	if(message_send == NULL){
		perror("Error during the asymmetric encryption\n");
		exit(-1);
	}
	// <encrypted_key> | <IV> | <ciphertext>
	send_obj(sock, message_send, send_len);

	//plaintext already freed by from_pt_to_DigEnv()
	free(message_send);
	send_len = 0;

	//delete public key from opBuffer
	#pragma optimize("", off)
   	memset(opBuffer, 0, dimOpBuffer);
	memset(buf, 0, lim);
	#pragma optimize("", on)
	free(opBuffer);
	free(buf);
	dimOpBuffer = 0;
	lim = 0;


	
	//RECEIVING DH PUBLIC KEY OF THE SERVER
	recv_len = receive_len(sock);
	message_recv = (unsigned char*) malloc(recv_len);
	if(message_recv == NULL){
		perror("Error during malloc()");
		exit(-1);
	}
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
	sumControl (DIM_NONCE, DIM_NONCE);
	extract_data_from_array(opBuffer, plaintext, DIM_NONCE, DIM_NONCE + DIM_NONCE);
	if(memcmp(opBuffer, myNonce, DIM_NONCE) != 0){
		perror("The two nonces are different\n");
		exit(-1);
	}
	free(opBuffer);
	dimOpBuffer = 0;

	//deserialization of the server DH public key
	subControlInt(pt_len, DIM_NONCE+DIM_NONCE);
	dimOpBuffer = pt_len - (DIM_NONCE+DIM_NONCE);
	opBuffer = (unsigned char*) malloc(dimOpBuffer);	//it'll contain the serialization of the DH public key of the server
	if(opBuffer == NULL){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(opBuffer, plaintext, DIM_NONCE+DIM_NONCE, pt_len);
	DHServerPubK = deserializePublicKey(opBuffer, dimOpBuffer);
	if(DHServerPubK == NULL){
		perror("Error during deserialization of the DH public key\n");
		exit(-1);
	}
	serverSymmetricKey = symmetricKeyDerivation_for_aes_128_gcm(dhPrivateKey, DHServerPubK);
	if(serverSymmetricKey == NULL){
		perror("Error during the derivation of the shared simmetric key");
		exit(-1);
	}

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
/*
	while(continueWhile){
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
				perror("scanf function has read a wrong number of items");
				exit(-1);
			}
			while(getchar() != '\n');		//cleaning the stdin buffer
			switch(command){
				case 1:		//online people
					pt_len = strlen("online_people") + 1;
					plaintext = (unsigned char*) malloc(pt_len);
					if(plaintext == NULL){
						perror("Error during malloc()");
						exit(-1);
					}
					strcpy(plaintext, "online_people");
					message_send = symmetricEncryption(plaintext, pt_len, serverSymmetricKey, &send_len);
					free(plaintext);
					send_obj(sock, message_send, send_len);
					recv_len = receive_len(sock);
					message_recv = (unsigned char*) malloc(recv_len);
					if(message_recv == NULL){
						perror("Error during malloc()");
						exit(-1);
					}
					receive_obj(sock, message_recv, recv_len);
					plaintext = symmetricDecription(message_recv, recv_len, &pt_len, serverSymmetricKey);
					printf("%s", plaintext);
					free(message_recv);
					free(message_send);
					free(plaintext);
					send_len = 0;
					recv_len = 0;
					break;

				case 2:		//request to talk
					printf("who do you want to send the request to?\n");
					opBuffer = (unsigned char*) malloc(DIM_USERNAME);
					if(opBuffer == NULL){
						perror("Error during malloc()");
						exit(-1);
					}
					if(fgets(opBuffer, DIM_USERNAME, stdin) == NULL){
						perror("Error during the fgets()");
						exit(-1);
					}
					charPointer = strchr(opBuffer, '\n');
					if(charPointer)
						*charPointer = '\0';
					sumControl(DIM_USERNAME, strlen("request") + 1);
					pt_len = DIM_USERNAME + strlen("request") + 1;
					plaintext = (unsigned char*) malloc(pt_len);
					if(plaintext == NULL){
						perror("Error during malloc()");
						exit(-1);
					}
					concat2Elements(plaintext, opBuffer, "request", DIM_USERNAME, strlen("request") + 1);
					//message to be sent has the format { <requested_username> | "request" }
					message_send = symmetricEncryption(plaintext, pt_len, serverSymmetricKey, &send_len);
					if(message_send == NULL){
						perror("Error during the encryption of the message");
						exit(-1);
					}
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
					if(message_recv == NULL){
						perror("Error during malloc()");
						exit(-1);
					}
					receive_obj(sock, message_recv, recv_len);
					plaintext = symmetricDecription(message_recv, recv_len, &pt_len, serverSymmetricKey);
					if(plaintext == NULL){
						perror("Error during the symmetric decription");
						exit(-1);
					}
					if(strcmp(plaintext, "refused") == 0){
						printf("Your request to talk with %s has been refused\n", opBuffer);
						free(opBuffer);
						free(plaintext);
						free(message_recv);
						dimOpBuffer = 0;
						break;
					}
					else if(strcmp(plaintext, "wrong_format") == 0){
						printf("Your request to talk with %s has not been sent because you have typed a username that does not exist\n", opBuffer);
						free(opBuffer);
						free(plaintext);
						free(message_recv);
						dimOpBuffer = 0;
						break;
					}
					else if(strcmp(plaintext, "busy") == 0){
						printf("%s is already busy in another conversation, keep trying later\n", opBuffer);
						free(opBuffer);
						free(plaintext);
						free(message_recv);
						dimOpBuffer = 0;
						break;
					}
					else if(strcmp(plaintext, "not_online") == 0){
						printf("%s is not online\n", opBuffer);
						free(opBuffer);
						free(plaintext);
						free(message_recv);
						dimOpBuffer = 0;
						break;
					}

					//request accepted, the plaintext is the serialized public key of the client
					if(communication_with_other_client(sock, plaintext, pt_len, myPrivK, true, opBuffer, serverSymmetricKey)){
						continueWhile = 0;
					}
					free(opBuffer);
					dimOpBuffer = 0;
					free(plaintext);
					pt_len = 0;
					free(message_recv);
					break;

				case 3:		//logout
					printf("Logging out\n");
					pt_len = strlen("logout") + 1;
					plaintext = (unsigned char*) malloc(pt_len);
					if(plaintext == NULL){
						perror("Error during malloc()");
						exit(-1);
					}
					strcpy(plaintext, "logout");
					message_send = symmetricEncryption(plaintext, pt_len, serverSymmetricKey, &send_len);
					free(plaintext);
					send_obj(sock, message_send, send_len);
					continueWhile = 0;
					free(message_send);
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
			if(message_recv == NULL){
				perror("Error during malloc()");
				exit(-1);
			}
			receive_obj(sock, message_recv, recv_len);
			//the message is encrypted by means of the symmetric key used by server and client
			plaintext = symmetricDecription(message_recv, recv_len, &pt_len, serverSymmetricKey);
			//the plaintext would have the format { <username that sent the request> | <"request"> }
			if(plaintext == NULL){
				perror("Error during the symmetric decription");
				exit(-1);
			}
			if(pt_len <= DIM_USERNAME){
				perror("Unrecognized format of the received message");
				exit(-1);
			}
			dimOpBuffer = pt_len - DIM_USERNAME;
			opBuffer = (unsigned char*) malloc(dimOpBuffer);
			if(opBuffer == NULL){
				perror("Error during malloc()");
				exit(-1);
			}
			extract_data_from_array(opBuffer, plaintext, DIM_USERNAME, pt_len);
			if(strcmp(opBuffer, "request") != 0){
				perror("Unrecognized format of the received message");
				exit(-1);
			}
			free(opBuffer);
			dimOpBuffer = DIM_USERNAME;
			opBuffer = (unsigned char*) malloc(dimOpBuffer);
			if(opBuffer == NULL){
				perror("Error during malloc()");
				exit(-1);
			}
			extract_data_from_array(opBuffer, plaintext, 0, DIM_USERNAME);
			free(plaintext);
			pt_len = 0;
			printf("You received a request to talk from %s. Type 'y' if you want to accept or 'n' if you want to refuse it\n", opBuffer);
			sumControl(DIM_USERNAME, 2);
			pt_len = DIM_USERNAME + 2;
			plaintext = (unsigned char*) malloc(pt_len);
			if(plaintext == NULL){
				perror("Error during malloc()");
				exit(-1);
			}
			if(fgets(plaintext, 2, stdin) == NULL){
				perror("Error during fgets()");
				exit(-1);
			}
			charPointer = strchr(plaintext, '\n');
			if(charPointer)
				*charPointer = '\0';
			concatElements(plaintext, opBuffer, 2, dimOpBuffer);
			message_send = symmetricEncryption(plaintext, pt_len, serverSymmetricKey, &send_len);
			if(message_send == NULL){
				perror("Error during the encryption of the message");
				exit(-1);
			}
			//send the message formatted like { <"y"/"n"> | <username that sent the request> }
			send_obj(sock, message_send, send_len);
			//I can use strcmp with plaintext because it contains for sure the '\0' character in position plaintext[1]
			free(message_send);
			free(message_recv);
			if(strcmp(plaintext, "y") == 0){
				//request accepted
				printf("you have accepted the request to talk with %s\n", opBuffer);
				recv_len = receive_len(sock);
				message_recv = (unsigned char*) malloc(recv_len);
				if(message_recv == NULL){
					perror("Error during malloc()");
					exit(-1);
				}
				//the message sent by the server contains the public key of the other client, encrypted by means of the simmetric key used by server and client
				plaintext = symmetricDecription(message_recv, recv_len, &pt_len, serverSymmetricKey);
				if(plaintext == NULL){
					perror("Error during symmetric decription");
					exit(-1);
				}
				if(communication_with_other_client(sock, plaintext, pt_len, myPivK, false, opBuffer, serverSymmetricKey))
					continueWhile = 0;
				free(plaintext);
				free(opBuffer);
				free(message_recv);
			}
			else{
				printf("you have rejected the request to talk with %s\n", opBuffer);
				free(opBuffer);
			}
		}
	}
	EVP_PKEY_free(myPrivK);
	EVP_PKEY_free(myPubK);
	X509_STORE_free(certStore);
	close(sock);
	printf("\nBye Bye!\n");
	return 0;
}
