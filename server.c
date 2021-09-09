//CLIENT

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
//#include "utility.c"
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

//list of integer
struct intList{
	int val;
	struct intList* next;
};

struct userStruct{
	bool online;	//true if the user is online, false otherwise
	bool busy;		//true if the user is already talking with someone, false otherwise
	char username[DIM_USERNAME];	//username of the user
	int numReq;		//Number of received request that has to be read yet
	int messagePipe[2];			//Pipe that contains the messages received by the user
	int requestPipe[2];			//Pipe that contains the requests to talk received by the user
	int lenPipe[2];		//Pipe that contains the length of the messages received by the user
	struct intList* cpt_len;	//list of lengths of the ciphertexts that are written in the file
	pthread_mutex_t userMutex;	//mutex that manage the access to the element of this structure and to the relative file
};

/*
//commento qui//Function that adds at the end of the list a new integer. Returns false in case of error
bool addIntList(struct intList** testa, int num){
	struct intList* p;
	if(*testa == NULL){
		//the list is empty
		*testa = (struct intList*) malloc(sizeof(struct intList));
		if(*testa == NULL)
			return false;
		(*testa) -> val = num;
		(*testa) -> next = NULL;
		return true;
	}
	p = *testa;
	while(p -> next!=NULL)
		p = p -> next;

	p -> next = (struct intList*) malloc(sizeof(struct intList));
	if(p -> next == NULL)
		return false;
	p = p->next;
	p -> val = num;
	p -> next = NULL;
}

//Function that remove the first element of a list. Returns false in case of error
bool removeFirstValueList(struct intList** testa){
	struct intList* s;
	if(*testa==NULL)
		return false;
	s = *testa;
	*testa = (*testa) -> next;
	free(s);
}

//Returns the sum of all the values of a list of integer. It returns -1 if the list is empty
int listTotalLen(struct intList* testa){
	int sum = 0;
	struct intList* p;
	p = testa;
	if(p == NULL)
		return -1;
	while(p != NULL){
		sum += p -> val;
		p = p -> next;
	}
	return sum;
}
*/

unsigned char myNonce[DIM_NONCE];
//pthread_mutex_t mutex; //commentato da Matte pthread_mutex_t mutex;
unsigned char username[DIM_USERNAME];
unsigned char clientNonce[DIM_NONCE];
unsigned char password[DIM_PASSWORD];


//Takes the username and returns its position in the array of users. It returns -1 in case of error
//commento qui
//Mapping from username to unsigned int
unsigned int mappingUserToInt(unsigned char* username){
	if (strcmp((char*)username, "matteo")==0) return 0;
	if (strcmp((char*)username, "gaia")==0) return 1;
	else return -1;
}

unsigned char* mappingIntToUser(unsigned int i){
	unsigned char* ret;
	if(i==0) {
		ret = (unsigned char*) malloc (strlen("matteo")+1);
		strncpy((char*)ret, "matteo", strlen("matteo") + 1);
	}
	else if(i==1) {
		ret = (unsigned char*) malloc (strlen("gaia")+1);
		strncpy((char*)ret, "gaia", strlen("gaia") + 1);
	}
	else {
		ret = (unsigned char*) malloc (strlen("")+1);
		strncpy((char*)ret, "", strlen("") + 1);
	}
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

/*
//Append a message in a file called messages/<username>_messages.txt if request is false. Append in requests/<username>_requests.txt otherwise
void forwardMessage(unsigned char* message, int messageLen, unsigned char* username, struct userStruct* users, bool request){
	int intUser;
	FILE* fd;
	char fileName[64];
	int ret;
	if(!request){
		strcpy(fileName, "messages/");
		strcat(fileName, username);
		strcat(fileName, "_messages.txt");
	}
	else{
		strcpy(fileName, "requests/");
		strcat(fileName, username);
		strcat(fileName, "_requests.txt");
	}
	intUser = mappingUserToInt(username);
	pthread_mutex_lock(&users[intUser].userMutex);
	fd = fopen(fileName, "ab");
	if(fd == NULL){
		perror("Error during fopen()");
		exit(-1);
	}
	ret = fwrite(message, messageLen, 1, fd);
	if(ret <= 0){
		perror("Error during the fwrite()");
		exit(-1);
	}
	ret = fclose(fd);
	if(ret != 0){
		perror("Error during fclose()");
		exit(-1);
	}
	if(!request){
		if(!addIntList(&(users[intUser].cpt_len), messageLen)){
			perror("Error during add into the list");
			exit(-1);
		}
		ret = kill(users[intUser].pid, signalNewMessage);
		if(ret != 0){
			perror("Error sending the signal");
			exit(-1);
		}
	}
	else{
		users[intUser].numReq++;
		ret = kill(users[intUser].pid, signalNewRequest);
		if(ret != 0){
			perror("Error sending the signal");
			exit(-1);
		}
	}
	pthread_mutex_unlock(&users[intUser].userMutex);
}*/

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
		/*if(!addIntList(&users[intReceiver].cpt_len, messageLen)){
			perror("Error adding an element in a list");
			exit(-1);
		}*/
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
		//the size of the first message is in the first element of the list
		//*messageLen = users[intReceiver].cpt_len -> val;
		read(users[intReceiver].lenPipe[readPipe], (void*)messageLen, sizeof(int));
		message = (unsigned char*) malloc(*messageLen);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		read(users[intReceiver].messagePipe[readPipe], message, *messageLen);
		/*if(!removeFirstValueList(&users[intReceiver].cpt_len)){
			perror("Error removing an element from a list");
			exit(-1);
		}*/
	}
	pthread_mutex_unlock(&users[intReceiver].userMutex);
	return message;
}

/*
//Read the first message in the file called messages/<username>_messages.txt if request is false. Read the first request in requests/<username>_requests.txt if it is true
unsigned char* takeAMessage(int* messageLen, unsigned char* username, struct userStruct* users, bool request){
	int intUser;
	unsigned char* message;
	unsigned char* remainingBuf;
	FILE* fd;
	char fileName[64];
	int ret;
	int remainingLen;	//length of the remaining part of the content of the file
	if(!request){
		strcpy(fileName, "messages/");
		strcat(fileName, username);
		strcat(fileName, "_messages.txt");
	}
	else{
		strcpy(fileName, "requests/");
		strcat(fileName, username);
		strcat(fileName, "_requests.txt");
	}
	intUser = mappingUserToInt(username);
	if(users[intUser].cpt_len == NULL){
		perror("The list is empty");
		exit(-1);
	}
	//the size of the first message is in the first element of the list
	if(!request){
		*messageLen = users[intUser].cpt_len -> val;
		remainingLen = listTotalLen(users[intUser].cpt_len) - *messageLen;
	}
	else{
		*messageLen = DIM_USERNAME + strlen("request") + 1;
		remainigLen = (users[intUser].numReq - 1) * (*messageLen);	//controllo overflow!!!
	}
	message = (unsigned char*) malloc(*messageLen);
	remainingBuf = (unsigned char*) malloc(remainingLen);
	if(!message || !remainingBuf){
		perror("Error during malloc()");
		exit(-1);
	}
	pthread_mutex_lock(&users[intUser].userMutex);
	fd = fopen(fileName, "rb");
	if(fd == NULL){
		perror("Error during fopen()");
		exit(-1);
	}
	ret = fread(message, *messageLen, 1, fd);
	if(ret <= 0){
		perror("Error during fread()");
		exit(-1);
	}
	ret = fseek(fd, *messageLen, SEEK_SET);
	if(ret != 0){
		perror("Error during fseek()");
		exit(-1);
	}
	ret = fread(remainingBuf, remainingLen, 1, fd);
	if(ret <= 0){
		perror("Error during fread()");
		exit(-1);
	}
	ret = fclose(fd);
	if(ret != 0){
		perror("Error during fclose()");
		exit(-1);
	}
	if(!request){
		if(!removeFirstValueList(&users[intUser].cpt_len)){
			perror("Error removing an element from the list");
			exit(-1);
		}
	}
	else{
		users[intUser].numReq--;
	}
	//Now I have to delete from the file the part I've just read
	fd = fopen(fileName, "wb");
	if(fd == NULL){
		perror("Error during fopen()");
		exit(-1);
	}
	ret = fwrite(remainingBuf, remainingLen, 1, fd);
	if(ret <= 0){
		perror("Error during the fwrite()");
		exit(-1);
	}
	ret = fclose(fd);
	if(ret != 0){
		perror("Error during fclose()");
		exit(-1);
	}
	pthread_mutex_unlock(&users[intUser].userMutex);
	free(remainingBuf);
	return message;
}*/

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
			if(users[i].online && i != intUser && (strlen(message) + strlen(users[i].username) + 7) < MAX_LEN_MESSAGE){	//message must be able to contain the length of the username + the heading + '\n'
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
	//COMPLETARE
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
	//sending of the request to the client
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
				printf("The client wants to exit\n");
				free(message);
				forwardMessage(communicatingClient, plaintext, pt_len, users, false);
				free(plaintext);
				return true;
			}
			free(plaintext);
			forwardMessage(communicatingClient, message, messageLen, users, false);
			free(message);
		}
		else if(FD_ISSET(users[intMyUser].messagePipe[readPipe], &recv_set)){
			//A new message destinated to the connected client is arrived
			message = readAMessage(myUser, &messageLen, users, false);
			//I have to control if the message is "<exit>". If it is so, it means that the other client has already communicated to the connected client
			//that he wants to exit and now it is communicating the same thing to the server
			if(strcmp(message, "<exit>") == 0){
				free(message);
				return false;
			}
			//If it is not "<exit>" I have to forward it to the connected client
			send_obj(socket_com, message, messageLen);
		}
	}
}

void handle_logout(int sock){
	//COMPLETARE
}
//commento qui
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


void handle_auth(int sock, struct userStruct* users, unsigned char* username){
	//Server retrieves his certificate and generate a nonce
	//char myNonce[DIM_NONCE];
	generateNonce(myNonce);
	
	X509* cert = getServerCertificate();


	//Send a certification over a socket

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
	printf("Certificate and nonce sended to the client \n");
	
	//Receive signed nonce from client
	int signed_size = receive_len(sock);
	unsigned char signed_msg[signed_size];
	receive_obj(sock, signed_msg, signed_size); 
	
	
	//Get the nonce and the username from the message I have received
	unsigned char get_username[DIM_USERNAME];
	//Get client nonce
	extract_data_from_array(clientNonce, signed_msg, 0, DIM_NONCE);
	sumControl(DIM_USERNAME, DIM_NONCE);
	int lim = DIM_USERNAME + DIM_NONCE;
	//Get username
	extract_data_from_array(get_username, signed_msg, DIM_NONCE, lim);
	sumControl(lim, DIM_NONCE);
	lim += DIM_NONCE;
	unsigned char signed_nonce[DIM_NONCE];
	//Get nonce
	extract_data_from_array(signed_nonce, signed_msg,DIM_USERNAME+DIM_NONCE, lim);
	subControlInt(signed_size, lim);
	int signature_len = signed_size - lim;
	unsigned char* signature = (unsigned char*) malloc(signature_len);
	if(!signature){
		perror("malloc");
		exit(-1);
	}
	//Get digital signature
	extract_data_from_array(signature, signed_msg, lim, signed_size);
	
	//Get the public key from pem file
	EVP_PKEY* pubkey = getUserPbkey(get_username);
	
	//Get file name
	

	//Signature verification
	bool ret =verifySignature(signature, myNonce, signature_len, DIM_NONCE, pubkey);
	//Comparison between myNonce and the nonce the client has sent me back
	bool ret2 = comparisonUnsignedChar(myNonce, signed_nonce, DIM_NONCE);
	if (ret && ret2){
		printf("%s authentication succeded \n", get_username);
		//I notify the result of the authentication to the user
		send_obj(sock, "OK", 3);

	}
	else {
		printf("Authentication of %s failed\n", get_username);
		//I notify the result of the authentication to the user
		send_obj(sock, "NO", 3);
		exit(-1);
		
	}
	EVP_PKEY_free(pubkey);
	free(signature);

	memset(username, 0, DIM_USERNAME);
	memcpy(username, get_username, DIM_USERNAME);
	
	setOnline(username, users);		
}

//Function that handles the negotiation of a shared symmetric session key by means of ephemeral Diffie-Hellman. It returns the symmetric key
unsigned char* establishDHExhange(int sock, unsigned char* username){
	//SYMMETRIC SESSION KEY NEGOTIATION BY MEANS OF EPHEMERAL DIFFIE-HELLMAN
	int lim = 0;
	EVP_PKEY* dhPrivateKey = generateDHParams();
	EVP_PKEY* myPrivK;
	EVP_PKEY* DHClientPubK;
	unsigned char* sessionKey;
	printf("DH parameters generated for session with %s \n", username);
	int dimOpBuffer = 0;
	unsigned char* opBuffer = NULL;
	unsigned char* buf = NULL;
	unsigned char* message_send = NULL;
	unsigned char* message_recv = NULL;
	int send_len=0;
	int recv_len =0;
	int pt_len = 0;
	unsigned char* plaintext = NULL;
	
	myPrivK = getMyPrivKey();
	//SERIALIZATION OF THE DH PUBLIC KEY
	opBuffer = serializePublicKey(dhPrivateKey, &dimOpBuffer);
	if(opBuffer == NULL){
		perror("Error during serialization of the DH public key\n");
		exit(-1);
	}
	
	//CREATION OF THE MESSAGE THAT HAS TO BE SENT TO THE SERVER (DH PUB KEY EXCHANGE)
	sumControl (DIM_NONCE, DIM_NONCE);
	lim = DIM_NONCE+DIM_NONCE;
	sumControl(lim, dimOpBuffer);
	lim += dimOpBuffer;
	buf = (unsigned char*) malloc(lim);
	/*sumControl(lim, DIM_NONCE);
	pt_len = lim + DIM_NONCE;
	plaintext = (unsigned char*) malloc(pt_len);*/
	//MESSAGE STRUCTURE: <serverNonce> | <clientNonce> | <pubkeyDH>
	concatElements(buf, myNonce, 0, DIM_NONCE);
	concatElements(buf, clientNonce, DIM_NONCE, DIM_NONCE);
	concatElements(buf, opBuffer, DIM_NONCE + DIM_NONCE, dimOpBuffer);
	/*subControlInt(pt_len,DIM_NONCE);
	concat2Elements(plaintext, myNonce, buf, DIM_NONCE, lim);*/

	EVP_PKEY* clientPubK = getUserPbkey(username);

	message_send = from_pt_to_DigEnv(buf, lim, clientPubK, &send_len);
	if(message_send == NULL){
		perror("Error during the asymmetric encryption\n");
		exit(-1);
	}
	//MESSAGE STRUCTURE: <encrypted_key> | <IV> | <ciphertext>
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

	//Get client public key
	recv_len = receive_len(sock);
	message_recv = (unsigned char*) malloc(recv_len);
	receive_obj(sock, message_recv, recv_len);
	//asymmetric encryption
	plaintext = from_DigEnv_to_PlainText(message_recv, recv_len, &pt_len, myPrivK);
	if(plaintext == NULL){
		perror("Error during the asimmetric decryption\n");
		exit(-1);
	}

	//Check on the nonce
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
	subControlInt(pt_len, DIM_NONCE+DIM_NONCE);
	dimOpBuffer = pt_len - (DIM_NONCE+DIM_NONCE);
	opBuffer = (unsigned char*) malloc(dimOpBuffer);	//it'll contain the serialization of the DH public key of the server
	extract_data_from_array(opBuffer, plaintext, DIM_NONCE+DIM_NONCE, pt_len);
	DHClientPubK = deserializePublicKey(opBuffer, dimOpBuffer);
	if(DHClientPubK == NULL){
		perror("Error during deserialization of the DH public key\n");
		exit(-1);
	}
	sessionKey = symmetricKeyDerivation_for_aes_128_gcm(dhPrivateKey, DHClientPubK);

	//now that we have a fresh symmetric key, some informations are useless
	EVP_PKEY_free(DHClientPubK);
	EVP_PKEY_free(dhPrivateKey);
	free(opBuffer);
	dimOpBuffer = 0;
	free(plaintext);
	free(message_recv);
	recv_len = 0;
	return sessionKey;
	printf("QUI\n");
	
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

	printf("Server in listening \n");
	fd_set master; 		//Main set 
	fd_set read_ready;	//Read set
	int fdmax;			//Max number of descriptors
	struct sockaddr_in indirizzo_client;
	int socket_com;
	socklen_t size = sizeof(indirizzo_client);
	int i = 0;
	
	
	/*int fd = open(argv[1], O_RDONLY);
	if(fd==-1){
		perror("Open fail");
		exit(-1);
	}*/
	struct userStruct* users = (struct userStruct*) mmap(NULL, TOT_USERS * sizeof(struct userStruct), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	
	if (users == MAP_FAILED){
		perror("MAP_FAILED");
		exit(-1);
	}
	initUsers(users);   
	//Inizializzo i due set
	/*
	FD_ZERO(&master);
	FD_ZERO(&read_ready);
	
	FD_SET(socket_ascolto, &master);	//Add the socket where I wait for connections requests on the main set
	fdmax = socket_ascolto;	
	FD_SET(socket_ascolto, &read_ready);
	while(1){
		read_ready = master;
		select(fdmax+1, &read_ready, NULL, NULL, NULL);
		for (i=0; i<fdmax+1; i++){
			if(FD_ISSET(i, &read_ready)){	//Descriptor ready
				if(i== socket_ascolto){		//The descriptor I have found is the one used for waiting connection requests
					//Il server si mette in ascolto su socket_ascolto
					socket_com = accept(socket_ascolto, (struct sockaddr*)&indirizzo_client, &size );
					//A request has arrived and I have made a new socket for the communication
					if (ret == -1){
						perror("accept");
						exit(-1);
					}
					FD_SET(socket_com, &master);	//Add the new socket to the main set
					if (socket_com > socket_ascolto) fdmax = socket_com;
					
					printf("Authentication request arrived\n");
						
					memcpy(password, pw, DIM_PASSWORD);
					handle_auth(socket_com, users);
					establishDHExhange(socket_com, sessionkey);
					while(1){
							FD_ZERO(&recv_set);
							FD_SET(i, &recv_set);
							
							char* command = ricevi_stringa(socket_com);
							printf("Ho ricevuto: %s \n", command); 
							//Gestione dei vari casi
							if (strcmp(command, "list")== 0)
								get_online_users(i);
							else if (strcmp(command, "request")==0){
								handle_send_request(i);
							}
							else if (strcmp(command, "logout")==0){
                                handle_logout(i);
							}
							
					}
					
					
					
				}
				else{	//It's not socket_ascolto, it's another one
					pid_t pid = fork();
					if (pid== -1){
						perror ("fork");
						exit(-1);
					}
					else if (pid == 0){		//I am in the child process
						close(socket_ascolto);
						
						
						while(1){
							FD_ZERO(&recv_set);
							FD_SET(i, &recv_set);
							
							char* command = ricevi_stringa(socket_com);
							printf("Ho ricevuto: %s \n", command); 
							//Gestione dei vari casi
							if (strcmp(command, "online_people")== 0)
								printf("List\n");
							else if (strcmp(command, "request")==0){
								printf("request\n");
								handle_send_request(i);
							}
							else if (strcmp(command, "logout")==0){
								printf("logout\n");
                                //handle_logout(i);
							}
							
						}

						close(i);
						FD_CLR(i, &master);		//Delete the socket from the main set
						//#pragma optimize("", off)
						//   	memset(session_key, 0, session_key_size);
						//#pragma optimize("", on)
						//   	free(session_key);
						exit(0);
						
					}
					//Parent process
					close(i);	//Closure socket
					FD_CLR(i, &master);		//Delete the socket from the main set
					memset(myNonce, 0, DIM_NONCE);
					memset(username, 0, DIM_USERNAME);
				}
			}
		}
	}*/
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
			handle_auth(socket_com, users, myUser);
			simKey = establishDHExhange(socket_com, myUser);
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
								printf("%s ha accettato %s\n", communicatingClient, myUser);
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
						sleep(20);
						communicatingClient = handle_recv_request(socket_com, users, myUser, simKey);
						if(communicatingClient != NULL){
							printf("%s ha accettato %s\n", myUser, communicatingClient);
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
