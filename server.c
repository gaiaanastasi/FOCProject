//CLIENT

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "crypto.c"
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <signal.h>

#define writePipe 1
#define readPipe 0

const int MAX_LEN_MESSAGE = 256;
char* server_port = "4242";

struct userStruct{
	bool online;	//true if the user is online, false otherwise
	bool busy;		//true if the user is already talking with someone, false otherwise
	char username[DIM_USERNAME];	//username of the user
	int numReq;		//Number of received request that has to be read yet
	int messagePipe[2];			//Pipe that contains the messages received by the user
	int requestPipe[2];			//Pipe that contains the requests to talk received by the user
	int lenPipe[2];		//Pipe that contains the length of the messages received by the user
	pthread_mutex_t userMutex;	//mutex that manage the access to the element of this structure and to the relative file
};

unsigned char myNonce[DIM_NONCE];
unsigned char username[DIM_USERNAME];
unsigned char clientNonce[DIM_NONCE];
unsigned char password[DIM_PASSWORD];
//list of the registered usernames
unsigned char* usernames[TOT_USERS] = {"matteo", "gaia", "clarissa", "elisa", "irene", "leonardo", "lorenzo", "luca"};

//Takes the username and returns its position in the array of users. It returns -1 in case of error
//Mapping from username to unsigned int
unsigned int mappingUserToInt(unsigned char* username){
	int i = 0;
	for(i = 0; i < TOT_USERS; i++){
		if(strcmp(usernames[i], username) == 0)
			return i;
	}
	return -1;
}

//Takes the integer index representing an user and returns its username
unsigned char* mappingIntToUser(unsigned int i){
	if(i < 0 || i >= TOT_USERS){
		return NULL;
	}
	unsigned char* ret = (unsigned char*) malloc(DIM_USERNAME);
	strcpy(ret, usernames[i]);
	return ret;
}

//Initialize the user structure
void initUsers(struct userStruct* users){
	pthread_mutexattr_t mutexattr;
	int i;
	int ret;
	unsigned char* username;
	int rc = pthread_mutexattr_init(&mutexattr);
	if (rc != 0){
		perror("pthread_mutexattr_init");
		exit(-1);
	}
	rc = pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);
	if (rc != 0){
		perror("pthread_mutexattr_setpshared");
		exit(-1);
	}
	for(i = 0; i < TOT_USERS; i++){
		rc = pthread_mutex_init(&users[i].userMutex, &mutexattr);
		if (rc != 0){
			perror("pthread_mutex_init");
			exit(-1);
		}
		//users[i].cpt_len = NULL;
		username = mappingIntToUser(i);
		if(!username){
			perror("Error during mappintgIntToUser()");
			exit(-1);
		}
		strcpy(users[i].username, username);
		free(username);
		users[i].online = false;
		users[i].busy = false;
		users[i].numReq = 0;
		ret = pipe(users[i].messagePipe);
		if(ret != 0){
			perror("Error during creation of the pipe");
			exit(-1);
		}
		ret = pipe(users[i].requestPipe);
		if(ret != 0){
			perror("Error during creation of the pipe");
			exit(-1);
		}
		ret = pipe(users[i].lenPipe);
		if(ret != 0){
			perror("Error during creation of the pipe");
			exit(-1);
		}
	}
}

//Mark new user as online
void setOnline(unsigned char* username, struct userStruct* users){
	//GLock on the shared resource
	int intUser = mappingUserToInt(username);
	if(intUser == -1){
		perror("user not found");
		exit(-1);
	}
	int ret = pthread_mutex_lock(&users[intUser].userMutex);
	if(ret != 0){
		perror("lock");
		exit(-1);
	}
	//Modify the variable 
	users[intUser].online = true;
	//Unlock the shared resource
	ret = pthread_mutex_unlock(&users[intUser].userMutex);
	if(ret != 0){
		perror("unlock");
		exit(-1);
	}
}

//Function that store a buffer in the relavtive pipe of the receiver. It store a message if request is false, a request otherwise
void forwardMessage(unsigned char* receiver, unsigned char* message, int messageLen, struct userStruct* users, bool request){
	int intReceiver;
	intReceiver = mappingUserToInt(receiver);
	if(intReceiver == -1){
		perror("Error during mappingUserToInt()");
		exit(-1);
	}
	pthread_mutex_lock(&users[intReceiver].userMutex);
	if(request){
		write(users[intReceiver].requestPipe[writePipe], message, messageLen);
		users[intReceiver].numReq++;
	} else{
		write(users[intReceiver].messagePipe[writePipe], message, messageLen);
		write(users[intReceiver].lenPipe[writePipe], (void*)&messageLen, sizeof(int));
	}
	pthread_mutex_unlock(&users[intReceiver].userMutex);
}

//Function that reads the first element of a pipe and returns it. It reads a message if request is false, a request otherwise
unsigned char* readAMessage(unsigned char* receiver, int* messageLen, struct userStruct* users, bool request){
	int intReceiver;
	unsigned char* message;
	intReceiver = mappingUserToInt(receiver);
	if(intReceiver == -1){
		perror("Error during mappingUserToInt()");
		exit(-1);
	}
	pthread_mutex_lock(&users[intReceiver].userMutex);
	if(request){
		*messageLen = DIM_USERNAME + strlen("request") + 1;
		message = (unsigned char*) malloc(*messageLen);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		read(users[intReceiver].requestPipe[readPipe], message, *messageLen);
		users[intReceiver].numReq--;
	} else{
		read(users[intReceiver].lenPipe[readPipe], (void*)messageLen, sizeof(int));
		message = (unsigned char*) malloc(*messageLen);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		read(users[intReceiver].messagePipe[readPipe], message, *messageLen);
	}
	pthread_mutex_unlock(&users[intReceiver].userMutex);
	return message;
}

unsigned int getNumberOfOnlineUsers(struct userStruct* users){
	unsigned int tot = 0;
	for (unsigned int i=0; i<TOT_USERS; i++){
		if(users[i].online) tot++;
	}
	return tot;
}

//Function that send a formatted string containing the message that reports the currently online users
void getOnlineUser (int sock, struct userStruct* users, unsigned char* myUsername, unsigned char* simKey){
	//Get the total number of active user
	unsigned int tot = getNumberOfOnlineUsers(users);
	unsigned char message[MAX_LEN_MESSAGE];
	unsigned char* sendMessage;
	int send_len;
	int conta = 1;
	char heading[6];	//the heading can contain an index composed by 3 digits
	int i = 0;
	int intUser = mappingUserToInt(myUsername);
	if (tot == 0) {
		perror("Error during getNumberOfOnlineUsers()");
		exit(-1);
	}
	if(tot > 1){
		strcpy(message, "\nThe currently online users are:\n");
		for(i = 0; i < TOT_USERS; i++){
			pthread_mutex_lock(&users[i].userMutex);
			if(users[i].online && i != intUser && (strlen(message) + strlen(users[i].username) + 7) < MAX_LEN_MESSAGE){	//message must be able to contain the length of the username + the heading + "\n"
				sprintf(heading, "%d) ", conta);
				strcat(message, heading);
				strcat(message, users[i].username);
				strcat(message, "\n");
				conta++;
			}
			pthread_mutex_unlock(&users[i].userMutex);
		}
	} else{
		strcpy(message, "\nYou are the only user that is currently online\n");
	}
	sendMessage = symmetricEncryption(message, strlen(message) + 1, simKey, &send_len);
	send_obj(sock, sendMessage, send_len);
	free(sendMessage);	
}

//Function that manage the sending of a request to talk. It returns the username of the requested user if request is accepted, NULL otherwise
unsigned char* handle_send_request(int sock, unsigned char* recv_message, int recv_len, struct userStruct* users, unsigned char* sender, unsigned char* simKey){
	unsigned char* receiver;
	unsigned char* requestString;
	unsigned char* answer;
	unsigned char* message;
	unsigned char* buffer;
	int bufferLen;
	int messageLen;
	int intReceiver;
	int intSender;
	int answerLen;
	int ret;
	char fileName[64];
	fd_set set;
	intSender = mappingUserToInt(sender);
	pthread_mutex_lock(&users[intSender].userMutex);
	users[intSender].busy = true;
	if(recv_len != (DIM_USERNAME + strlen("request") + 1)){
		message = malloc(strlen("wrong_format") + 1);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		strcpy(message, "wrong_format");
		buffer = symmetricEncryption(message, strlen(message) + 1, simKey, &bufferLen);
		send_obj(sock, buffer, bufferLen);
		free(message);
		free(buffer);
		users[intSender].busy = false;
		pthread_mutex_unlock(&users[intSender].userMutex);
		return NULL;
	}
	requestString = (unsigned char*) malloc(strlen("request") + 1);
	if(!requestString){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(requestString, recv_message, DIM_USERNAME, recv_len);
	if(strcmp(requestString, "request") != 0){
		message = malloc(strlen("wrong_format") + 1);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		strcpy(message, "wrong_format");
		buffer = symmetricEncryption(message, strlen(message) + 1, simKey, &bufferLen);
		send_obj(sock, buffer, bufferLen);
		free(message);
		free(buffer);
		users[intSender].busy = false;
		pthread_mutex_unlock(&users[intSender].userMutex);
		return NULL;
	}
	free(requestString);
	receiver = (unsigned char*) malloc(DIM_USERNAME);
	if(!receiver){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(receiver, recv_message, 0, DIM_USERNAME);
	intReceiver = mappingUserToInt(receiver);
	//Control if the username exists and if the relative user is online and not busy
	if(intReceiver < 0){
		message = malloc(strlen("wrong_format") + 1);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		strcpy(message, "wrong_format");
		buffer = symmetricEncryption(message, strlen(message) + 1, simKey, &bufferLen);
		send_obj(sock, buffer, bufferLen);
		free(message);
		free(buffer);
		users[intSender].busy = false;
		pthread_mutex_unlock(&users[intSender].userMutex);
		return NULL;
	}
	pthread_mutex_lock(&users[intReceiver].userMutex);
	if(users[intReceiver].online == false){
		message = malloc(strlen("not_online") + 1);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		strcpy(message, "not_online");
		buffer = symmetricEncryption(message, strlen(message) + 1, simKey, &bufferLen);
		send_obj(sock, buffer, bufferLen);
		free(message);
		free(buffer);
		users[intSender].busy = false;
		pthread_mutex_unlock(&users[intSender].userMutex);
		pthread_mutex_unlock(&users[intReceiver].userMutex);
		return NULL;
	}
	if(users[intReceiver].busy == true){
		message = malloc(strlen("busy") + 1);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		strcpy(message, "busy");
		buffer = symmetricEncryption(message, strlen(message) + 1, simKey, &bufferLen);
		send_obj(sock, buffer, bufferLen);
		free(message);
		free(buffer);
		users[intSender].busy = false;
		pthread_mutex_unlock(&users[intSender].userMutex);
		pthread_mutex_unlock(&users[intReceiver].userMutex);
		return NULL;
	}
	pthread_mutex_unlock(&users[intReceiver].userMutex);
	pthread_mutex_unlock(&users[intSender].userMutex);
	//Creation of the request to be sent to the other user
	messageLen = DIM_USERNAME + strlen("request") + 1;
	message = (unsigned char*) malloc(messageLen);
	if(!message){
		perror("Error during malloc()");
		exit(-1);
	}
	memcpy(message, sender, DIM_USERNAME);
	concatElements(message, "request", DIM_USERNAME, strlen("request") + 1);
	forwardMessage(receiver, message, messageLen, users, true);
	free(message);
	FD_ZERO(&set);
	FD_SET(users[intSender].messagePipe[readPipe], &set);
	//waiting for the answer
	ret = select(users[intSender].messagePipe[readPipe] + 1, &set, NULL, NULL, NULL);
	if(ret < 0){
		perror("Error during select()");
		exit(-1);
	}
	if(FD_ISSET(users[intSender].messagePipe[readPipe], &set)){
		//the answer is arrived
		answer = readAMessage(sender, &answerLen, users, false);
		if(strcmp(answer, "y") == 0){
			//request accepted
			free(answer);
			return receiver;
		} else {
			//request refused
			messageLen = strlen("refused") + 1;
			message = (unsigned char*) malloc(messageLen);
			if(!message){
				perror("Error during malloc()");
				exit(-1);
			}
			strcpy(message, "refused");
			buffer = symmetricEncryption(message, strlen(message) + 1, simKey, &bufferLen);
			send_obj(sock, buffer, bufferLen);
			users[intSender].busy = false;
			free(answer);
			return NULL;
		}
	}
}

//Function that manages the receiving of a request. It returns username of the requesting user if request is accepted, NULL otherwise
unsigned char* handle_recv_request(int sock, struct userStruct* users, unsigned char* receiver, unsigned char* simKey){
	int intReceiver;
	unsigned char* message;
	unsigned char* buffer;
	unsigned char* answer;
	unsigned char* sender;
	int intSender;
	int bufferLen;
	int messageLen;

	intReceiver = mappingUserToInt(receiver);
	pthread_mutex_lock(&users[intReceiver].userMutex);
	users[intReceiver].busy = true;
	pthread_mutex_unlock(&users[intReceiver].userMutex);

	message = readAMessage(receiver, &messageLen, users, true);
	sender = (unsigned char*) malloc(DIM_USERNAME);
	if(!sender){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(sender, message, 0, DIM_USERNAME);
	intSender = mappingUserToInt(sender);
	buffer = symmetricEncryption(message, messageLen, simKey, &bufferLen);
	if(buffer == NULL){
		perror("Error during symmetric encryption");
		exit(-1);
	}
	//sending the request to the client
	send_obj(sock, buffer, bufferLen);
	free(buffer);
	free(message);
	bufferLen = receive_len(sock);
	buffer = (unsigned char*) malloc(bufferLen);
	if(!buffer){
		perror("Error during malloc()");
		exit(-1);
	}
	//receiving the answer
	receive_obj(sock, buffer, bufferLen);
	message = symmetricDecription(buffer, bufferLen, &messageLen, simKey);
	answer = (unsigned char*) malloc(2);
	if(!answer){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(answer, message, 0, 2);
	free(message);
	forwardMessage(sender, answer, strlen(answer) + 1, users, false);
	if(strcmp(answer, "y") == 0){
		free(answer);
		return sender;
	}
	else{
		pthread_mutex_lock(&users[intReceiver].userMutex);
		users[intReceiver].busy = false;
		pthread_mutex_unlock(&users[intReceiver].userMutex);
		free(answer);
		return NULL;
	}
}

//Function that handles the forwarding of messages from a client to another one. It returns true if the connected username wanted to exit, false otherwise
bool handle_forward_messages(int socket_com, struct userStruct* users, unsigned char* myUser, unsigned char* simKey, unsigned char* communicatingClient){
	fd_set recv_set;
	int greatest, ret;
	unsigned char* message;
	int messageLen;
	unsigned char* plaintext;
	int pt_len;
	int intMyUser = mappingUserToInt(myUser);
	if(intMyUser < 0){
		perror("Error during mappingUserToInt()");
		exit(-1);
	}
	while(1){
		//communications can arrive from other processes (messages) or from the connected client
		FD_ZERO(&recv_set);
		FD_SET(socket_com, &recv_set);
		FD_SET(users[intMyUser].messagePipe[readPipe], &recv_set);
		if(socket_com > users[intMyUser].messagePipe[readPipe])
			greatest = socket_com;
		else
			greatest = users[intMyUser].messagePipe[readPipe];
		ret = select(greatest + 1, &recv_set, NULL, NULL, NULL);
		if(ret < 0){
			perror("Error during select()");
			exit(-1);
		}
		if(FD_ISSET(socket_com, &recv_set)){
			//A new message sent from the connected client is arrived
			messageLen = receive_len(socket_com);
			message = (unsigned char*) malloc(messageLen);
			if(!message){
				perror("Error during malloc()");
				exit(-1);
			}
			receive_obj(socket_com, message, messageLen);
			//I have to try to decrypt the message with my simKey. If the message is encrypted by means of my simKey, the message will be "<exit>"
			plaintext = symmetricDecription(message, messageLen, &pt_len, simKey);
			if(strcmp(plaintext, "<exit>") == 0){
				//The connected client wants to exit
				printf("The client wants to exit\n");
				free(message);
				forwardMessage(communicatingClient, plaintext, pt_len, users, false);
				free(plaintext);
				pthread_mutex_lock(&users[intMyUser].userMutex);
				users[intMyUser].busy = false;
				pthread_mutex_unlock(&users[intMyUser].userMutex);
				return true;
			}
			else{
				forwardMessage(communicatingClient, plaintext, pt_len, users, false);
				free(plaintext);
				free(message);
			}
		}
		else if(FD_ISSET(users[intMyUser].messagePipe[readPipe], &recv_set)){
			//A new message destinated to the connected client is arrived
			plaintext = readAMessage(myUser, &pt_len, users, false);
			//I have to control if the message is "<exit>". If it is so, it means that the other client has already communicated to the connected client
			//that he wants to exit and now it is communicating the same thing to the server
			if(strcmp(plaintext, "<exit>") == 0){
				pthread_mutex_lock(&users[intMyUser].userMutex);
				users[intMyUser].busy = false;
				pthread_mutex_unlock(&users[intMyUser].userMutex);
				free(plaintext);
				return false;
			}
			//If it is not "<exit>" I have to forward it to the connected client
			message = symmetricEncryption(plaintext, pt_len, simKey, &messageLen);
			send_obj(socket_com, message, messageLen);
			free(message);
			free(plaintext);
		}
	}
}

X509* getServerCertificate (){
	///GET THE CERTIFICATE FROM PEM FILE
	X509* cert;
	FILE* file = fopen("certificates/server_cert.pem", "r");
	if(!file){
		perror("fopen");
		exit(-1);
	}
	cert = PEM_read_X509(file, NULL, NULL, NULL);
	if(!cert) {
		perror("certificate not found");
		exit(-1);
	}
	fclose(file); 
	return cert;
	
}

EVP_PKEY* getMyPrivKey(){
	FILE* file = fopen("certificates/serverprvkey.pem", "r");
	if(file == NULL){
		perror("Error during the opening of a file\n");
		exit(-1);
	}
	EVP_PKEY* myPrivK = PEM_read_PrivateKey(file, NULL, NULL, password);
	if(myPrivK == NULL){
		perror("Error during the loading of the private key, maybe wrong password?\n");
		exit(-1);
	}
	fclose(file);
	return myPrivK;
}


void handle_auth(int sock){
	//Server retrieves his certificate and generate a nonce
	generateNonce(myNonce);
	
	X509* cert = getServerCertificate();


	//Send the certification over a socket
	unsigned char* cert_buf = NULL;
	unsigned int cert_size = i2d_X509(cert, &cert_buf);
	if(cert_size < 0) {
		perror("certificate size error");
		exit(-1);
	}

	sumControl (cert_size, DIM_NONCE);
	
	size_t size_msg = cert_size + DIM_NONCE;
	unsigned char msg[size_msg];
	memset(msg, 0, size_msg);
	concat2Elements(msg, myNonce, cert_buf, DIM_NONCE, cert_size);
	
	
	OPENSSL_free(cert_buf);
	send_obj(sock, msg, size_msg);
	printf("Certificate and nonce sent to the client \n");
}

//Function that handles the negotiation of a shared symmetric session key by means of ephemeral Diffie-Hellman. It returns the symmetric key
unsigned char* establishDHExhange(int sock, unsigned char* username, struct userStruct* users){
	//SYMMETRIC SESSION KEY NEGOTIATION BY MEANS OF EPHEMERAL DIFFIE-HELLMAN
	int lim = 0;
	EVP_PKEY* dhPrivateKey = generateDHParams();
	EVP_PKEY* myPrivK;
	EVP_PKEY* clientPubK;
	EVP_PKEY* DHClientPubK;
	unsigned char* sessionKey;
	//printf("DH parameters generated for session with %s \n", username);
	int dimOpBuffer = 0;
	unsigned char* opBuffer = NULL;
	unsigned char* buf = NULL;
	unsigned char* message_send = NULL;
	unsigned char* message_recv = NULL;
	unsigned char* signature;
	int signatureLen;
	int send_len=0;
	int recv_len =0;
	int pt_len = 0;
	unsigned char* plaintext = NULL;
	
	myPrivK = getMyPrivKey();

	//RECEIVING MESSAGE FROM THE CLIENT (DH PUBKEY EXCHANGE)
	signatureLen = receive_len(sock);
	recv_len = receive_len(sock);
	message_recv = (unsigned char*) malloc(recv_len);
	if(!message_recv){
		perror("Error using malloc()");
		exit(-1);
	}
	receive_obj(sock, message_recv, recv_len);
	extract_data_from_array(username, message_recv, 0, DIM_USERNAME);
	lim = recv_len - DIM_USERNAME;
	buf = (unsigned char*) malloc(lim);
	if(!buf){
		perror("Error during malloc()");
		exit(-1);
	}
	setOnline(username, users);
	clientPubK = getUserPbkey(username);
	extract_data_from_array(buf, message_recv, DIM_USERNAME, recv_len);
	//asymmetric decryption
	plaintext = from_DigEnv_to_PlainText(buf, lim, &pt_len, myPrivK);
	if(plaintext == NULL){
		perror("Error during the asimmetric decryption\n");
		exit(-1);
	}
	//The plaintext has the format { <clientNonce> | <serverNonce> | <ClientDHPublicKey> | <signature> }
	subControlInt(pt_len, signatureLen);
	signature = (unsigned char*) malloc(signatureLen);
	if(!signature){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(signature, plaintext, pt_len - signatureLen, pt_len);
	dimOpBuffer = pt_len - signatureLen;
	opBuffer = (unsigned char*) malloc(dimOpBuffer);
	if(!opBuffer){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(opBuffer, plaintext, 0, pt_len - signatureLen);
	if(!verifySignature(signature, opBuffer, signatureLen, dimOpBuffer, clientPubK)){
		perror("error verifying the signature");
		exit(-1);
	}
	free(opBuffer);
	free(signature);
	//Take client nonce
	dimOpBuffer = DIM_NONCE;
	opBuffer = (unsigned char*) malloc(dimOpBuffer);
	if(!opBuffer){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(clientNonce, plaintext, 0, DIM_NONCE);
	free(opBuffer);
	//Check for my nonce
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
	
	//Deserialization of the client's DH public key
	subControlInt(pt_len, DIM_NONCE+DIM_NONCE+signatureLen);
	dimOpBuffer = pt_len - (DIM_NONCE+DIM_NONCE+signatureLen);
	opBuffer = (unsigned char*) malloc(dimOpBuffer);	//it'll contain the serialization of the DH public key of the server
	extract_data_from_array(opBuffer, plaintext, DIM_NONCE+DIM_NONCE, pt_len - signatureLen);
	DHClientPubK = deserializePublicKey(opBuffer, dimOpBuffer);
	if(DHClientPubK == NULL){
		perror("Error during deserialization of the DH public key\n");
		exit(-1);
	}
	free(opBuffer);
	free(plaintext);
	
	//SERIALIZATION OF THE DH PUBLIC KEY
	opBuffer = serializePublicKey(dhPrivateKey, &dimOpBuffer);
	if(opBuffer == NULL){
		perror("Error during serialization of the DH public key\n");
		exit(-1);
	}
	
	//CREATION OF THE MESSAGE THAT HAS TO BE SENT TO THE CLIENT (DH PUB KEY EXCHANGE)
	sumControl (DIM_NONCE, DIM_NONCE);
	sumControl(DIM_NONCE + DIM_NONCE, dimOpBuffer);
	lim = DIM_NONCE+DIM_NONCE + dimOpBuffer;
	buf = (unsigned char*) malloc(lim);
	//MESSAGE STRUCTURE: <serverNonce> | <clientNonce> | <pubkeyDH> | <signature>
	concatElements(buf, myNonce, 0, DIM_NONCE);
	concatElements(buf, clientNonce, DIM_NONCE, DIM_NONCE);
	concatElements(buf, opBuffer, DIM_NONCE + DIM_NONCE, dimOpBuffer);
	signature = (unsigned char*) malloc(EVP_PKEY_size(myPrivK));
	if(!signature){
		perror("Error during malloc()");
		exit(-1);
	}
	signatureFunction(buf, lim, signature, &signatureLen, myPrivK);
	sumControl(lim, signatureLen);
	pt_len = lim + signatureLen;
	plaintext = (unsigned char*) malloc(pt_len);
	if(!plaintext){
		perror("Error during malloc()");
		exit(-1);
	}
	concat2Elements(plaintext, buf, signature, lim, signatureLen);
	
	message_send = from_pt_to_DigEnv(plaintext, pt_len, clientPubK, &send_len);
	if(message_send == NULL){
		perror("Error during the asymmetric encryption\n");
		exit(-1);
	}
	send_int(sock, signatureLen);
	send_obj(sock, message_send, send_len);

	//plaintext already freed by from_pt_to_DigEnv()
	free(message_send);
	send_len = 0;
	free(signature);
	
	//delete public key from opBuffer
#pragma optimize("", off)
   	memset(opBuffer, 0, dimOpBuffer);
	memset(buf, 0, lim);
#pragma optimize("", on)
	free(opBuffer);
	free(buf);
	dimOpBuffer = 0;
	lim = 0;
	
	sessionKey = symmetricKeyDerivation_for_aes_128_gcm(dhPrivateKey, DHClientPubK);

	//now that we have a fresh symmetric key, some informations are useless
	EVP_PKEY_free(DHClientPubK);
	EVP_PKEY_free(dhPrivateKey);
	EVP_PKEY_free(clientPubK);
	dimOpBuffer = 0;
	free(message_recv);
	recv_len = 0;
	return sessionKey;	
}



int main (int argc, const char** argv){
    int socket_ascolto; //Socket where our server wait for connections
	printf("Insert password:");
	unsigned char pw[DIM_PASSWORD];
	getPassword(pw);
	printf("\n");
				
	socket_ascolto = socket(AF_INET, SOCK_STREAM, 0);
	
	if(socket_ascolto == -1){
		perror("Socket");
		exit(-1);
	}
	else printf("Listening socket opened \n");
	struct sockaddr_in indirizzo_server;
	//Parameters for server socket
	memset(&indirizzo_server, 0, sizeof(indirizzo_server));		//Clean 
	int porta = atoi(server_port);
	indirizzo_server.sin_family = AF_INET;
	indirizzo_server.sin_port = htons(porta);
	indirizzo_server.sin_addr.s_addr = htonl(INADDR_ANY);
	
	
	int ret;
    //This server will use the port that it has already used before
	int yes = 1;
    if (setsockopt(socket_ascolto, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1)
    {
        perror("setsockopt");
        exit(-1);
    }
    
    //bind on socket 
	ret = bind(socket_ascolto, (struct sockaddr*)&indirizzo_server, sizeof(indirizzo_server));
	if (ret == -1){
		perror("bind");
		exit(-1);	
	}
    //socket_ascolto is the socket used for receiving connection requests
	ret = listen(socket_ascolto, 10);
	if (ret == -1){
		perror("listen");
		exit(-1);
	}

	printf("Server is listening \n");
	fd_set master; 		//Main set 
	fd_set read_ready;	//Read set
	int fdmax;			//Max number of descriptors
	struct sockaddr_in indirizzo_client;
	int socket_com;
	socklen_t size = sizeof(indirizzo_client);
	int i = 0;
	
	struct userStruct* users = (struct userStruct*) mmap(NULL, TOT_USERS * sizeof(struct userStruct), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	
	if (users == MAP_FAILED){
		perror("MAP_FAILED");
		exit(-1);
	}
	initUsers(users);   
	int intMyUser;				//integer related to the username of the logged user
	unsigned char myUser[DIM_USERNAME];	//username of the logged user
	unsigned char* simKey;			//simmetric shared key used for communicating with the client
	fd_set recv_set;
	pid_t pid;
	int greatest;
	bool waitingRequest = true;		//true if the connected client has not accepted a request to talk yet
	bool waitingMessage = false;		//true if the connected client has already accepted a request to talk
	unsigned char* recv_message;
	int recv_len;
	unsigned char* plaintext;
	int pt_len;
	unsigned char* communicatingClient = NULL;	//username of the client with wich the connected client is talking to
	EVP_PKEY* communicatingClient_pubKey;	//public key of the user that accepted to talk with the connected client
	unsigned char* buffer;
	int bufferLen;
	while(1){
		socket_com = accept(socket_ascolto, (struct sockaddr*)&indirizzo_client, &size );
		pid = fork();
		if(pid == 0){
			//processo figlio, gestisce comunicazione
			close(socket_ascolto);
			printf("Authentication request arrived\n");			
			memcpy(password, pw, DIM_PASSWORD);
			handle_auth(socket_com);
			simKey = establishDHExhange(socket_com, myUser, users);
			intMyUser = mappingUserToInt(myUser);
			if(intMyUser < 0){
				perror("Error during mappingUserToInt()");
				exit(-1);
			}
			while(waitingRequest || waitingMessage){
				while(waitingRequest){
				//Communications can arrive from other processes (requests) or from the connected client
					FD_ZERO(&recv_set);
					FD_SET(socket_com, &recv_set);
					FD_SET(users[intMyUser].requestPipe[readPipe], &recv_set);
					if(socket_com > users[intMyUser].requestPipe[readPipe])
						greatest = socket_com;
					else
						greatest = users[intMyUser].requestPipe[readPipe];
					ret = select(greatest + 1, &recv_set, NULL, NULL, NULL);
					if(ret < 0){
						perror("Error during select()");
						exit(-1);
					}
					if(FD_ISSET(socket_com, &recv_set)){
						//A new message from the client is arrived
						recv_len = receive_len(socket_com);
						recv_message = (unsigned char*) malloc(recv_len);
						if(!recv_message){
							perror("Error during malloc()");
							exit(-1);
						}
						receive_obj(socket_com, recv_message, recv_len);
						plaintext = symmetricDecription(recv_message, recv_len, &pt_len, simKey);
						if(strcmp(plaintext, "online_people") == 0)
							getOnlineUser(socket_com, users, myUser, simKey);
						else if(strcmp(plaintext, "logout") == 0){
							waitingMessage = waitingRequest = false;
							break;
						}
						else{
							communicatingClient = handle_send_request(socket_com, plaintext, pt_len, users, myUser, simKey);
							if(communicatingClient != NULL){
								free(plaintext);
								waitingMessage = true;
								waitingRequest = false;
								communicatingClient_pubKey = getUserPbkey(communicatingClient);
								plaintext = serializePublicKey(communicatingClient_pubKey, &pt_len);
								if(!plaintext){
									perror("Error during serialization of the public key\n");
									exit(-1);
								}
								buffer = symmetricEncryption(plaintext, pt_len, simKey, &bufferLen);
								if(!buffer){
									perror("Error during encryption of the message\n");
									exit(-1);
								}
								send_obj(socket_com, buffer, bufferLen);
								free(buffer);
							}
						}
						free(plaintext);
						free(recv_message);
					}
					else if(FD_ISSET(users[intMyUser].requestPipe[readPipe], &recv_set)){
						//A new request is arrived
						communicatingClient = handle_recv_request(socket_com, users, myUser, simKey);
						if(communicatingClient != NULL){
							waitingMessage = true;
							waitingRequest = false;
							communicatingClient_pubKey = getUserPbkey(communicatingClient);
							plaintext = serializePublicKey(communicatingClient_pubKey, &pt_len);
							if(!plaintext){
								perror("Error during serialization of the public key\n");
								exit(-1);
							}
							buffer = symmetricEncryption(plaintext, pt_len, simKey, &bufferLen);
							if(!buffer){
								perror("Error during encryption of the message\n");
								exit(-1);
							}
							send_obj(socket_com, buffer, bufferLen);
							free(buffer);
							free(plaintext);
						}
					}
				}
				if(waitingMessage){
					//The user has accepted a request to talk
					if(handle_forward_messages(socket_com, users, myUser, simKey, communicatingClient) == true){
						//myUser wants to exit, I can delete the connection
						waitingMessage = waitingRequest = false;
					} else{
						waitingRequest = true;
						waitingMessage = false;
					}
				}
			}
			pthread_mutex_lock(&users[intMyUser].userMutex);
			users[intMyUser].online = false;
			pthread_mutex_unlock(&users[intMyUser].userMutex);
			printf("\n%s has logged out\n", myUser);
			free(simKey);
			close(socket_com);
			exit(1);
		} else {
			//processo padre, si rimette in attesa di altre comunicazioni
			close(socket_com);
		}
	}
	close(socket_ascolto);
}
