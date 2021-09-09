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

#define signalNewMessage 10
#define signalNewRequest 12
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
	int pid;		//Process id of the process that is managing the connection of the user
	struct intList* cpt_len;	//list of lengths of the ciphertexts that are written in the file
	pthread_mutex_t userMutex;	//mutex that manage the access to the element of this structure and to the relative file
};

/*//Function that adds at the end of the list a new integer. Returns false in case of error
bool addIntList(struct intLista** testa, int num){
	struct intLista* p;
	if(*testa == NULL){
		//the list is empty
		*testa = (int*) malloc(sizeof(struct intList));
		if(*testa == NULL)
			return false;
		(*testa) -> val = num;
		(*testa) -> next = NULL;
		return true;
	}
	p = *testa;
	while(p -> next!=NULL)
		p = p -> next;

	p -> next = (struct intLista*) malloc(sizeof(struct intList));
	if(p -> next == NULL)
		return false;
	p = p->next;
	p -> val = num;
	p -> next = NULL;
}

//Function that remove the first element of a list. Returns false in case of error
bool removeFirstValueList(struct intLista** testa){
	struct intLista* s;
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
/*//Mapping from username to unsigned int
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
	if(i==1) {
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
		users[i].cpt_len = NULL;
		username = mappingIntToUser(i);
		strcpy(users[i].username, username);
		free(username);
		users[i].online = false;
		users[i].busy = false;
		users[i].numReq = 0;
	}
}
*/
/* commentato da Matte
//Mark new user as online
void addUsertoList(unsigned char* username, bool* online_users){
	//GLock on the shared resource
	int user = mappingUserToInt(username);
	if(user == -1){
		perror("user not found");
		exit(-1);
	}
	int ret = pthread_mutex_lock(&mutex);
	if(ret != 0){
		perror("lock");
		exit(-1);
	}
	//Modify the variable 
	online_users[user] = true;
	//Unlock the shared resource
	ret = pthread_mutex_unlock(&mutex);
	if(ret != 0){
		perror("lock");
		exit(-1);
	}
	
	
}*/
/*
//Mark new user as online
void addUsertoList(unsigned char* username, struct userStruct* users){
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
}

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
	//Now I have to delete from the file the part just read
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
}

unsigned int getNumberOfOnlineUsers(struct userStruct* users){
	unsigned int tot = 0;
	for (unsigned int i=0; i<TOT_USERS; i++){
		if(users[i].online) tot++;
	}
	return tot;
}

//Function that send a formatted string containing the message that reports the currently online users
void getOnlineUser (int sock, struct userStruct* users, unsigned char* myUsername){
	//Get the total number of active user
	//unsigned int tot = getNumberOfOnlineUsers(users);
	unsigned char message[MAX_LEN_MESSAGE];
	char heading[6];	//the heading can contain an index composed by 3 digits
	int i = 0;
	int intUser = mappingUserToInt(myUsername);
	if (tot == 0) {
		perror("Error during getNumberOfOnlineUsers()");
		exit(-1);
	}
	strcpy(message, "\nThe currently online users are:\n");
	for(i = 0; i < TOT_USERS; i++){
		pthread_mutex_lock(&users[i].userMutex);
		if(users[i].online && i != intUser && (strlen(message) + strlen(users[i].username) + 7) < MAX_LEN_MESSAGE){	//message must be able to contain the length of the username + the heading + '\n'
			sprintf(heading, "%d) ", i);
			strcat(message, heading);
			strcat(message, users[i].username);
			strcat(message, "\n");
		}
		pthread_mutex_unlock(&users[i].userMutex);
	}
	send_obj(sock, message, strlen(message) + 1);
	//send_obj(sock, online, tot); DEVO FARE UNA SEND PER MANDARE VETTORI DI STRINGHE	
}

//Function that manage the sending of a request to talk. It returns true if the request has been accepted, false otherwise
bool handle_send_request(int sock, unsigned char* recv_message, int recv_len, struct userStruct* users, unsigned char* requesting_username){
	//COMPLETARE
	unsigned char* requested_username;
	unsigned char* requestString;
	unsigned char* message;
	int messageLen;
	int intUser;
	fd_set set;
	FILE* fd;
	char fileName[64];
	if(recv_len != (DIM_USERNAME + strlen("request") + 1)){
		message = malloc(strlen("wrong_format") + 1);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		strcpy(message, "wrong_format");
		send_obj(sock, message, strlen(message) + 1);
		free(message);
		return false;
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
		send_obj(sock, message, strlen(message) + 1);
		free(message);
		return false;
	}
	requested_username = (unsigned char*) malloc(DIM_USERNAME);
	if(!requested_username){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(requested_username, recv_message, 0, DIM_USERNAME);
	intUser = mappingUserToInt(requested_username);
	//Control if the username exists and if the relative user is online and not busy
	if(intUser < 0){
		message = malloc(strlen("wrong_format") + 1);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		strcpy(message, "wrong_format");
		send_obj(sock, message, strlen(message) + 1);
		free(message);
		return false;
	}
	if(users[intUser].online == false){
		message = malloc(strlen("not_online") + 1);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		strcpy(message, "not_online");
		send_obj(sock, message, strlen(message) + 1);
		free(message);
		return false;
	}
	if(users[intUser].busy == true){
		message = malloc(strlen("busy") + 1);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		strcpy(message, "busy");
		send_obj(sock, message, strlen(message) + 1);
		free(message);
		return false;
	}
	//Creation of the message to be sent to the other user
	messageLen = DIM_USERNAME + strlen("request") + 1;
	message = (unsigned char*) malloc(messageLen);
	if(!message){
		perror("Error during malloc()");
		exit(-1);
	}
	memcpy(message, requesting_username, DIM_USERNAME);
	concatElements(message, "request", DIM_USERNAME, strlen("request") + 1);
	forwardMessage(message, messageLen, requested_username, users, true);
	//I have to wait until the other client sends the answer
	strcpy(fileName, "requests/");
	strcat(fileName, requesting_username);
	strcat(fileName, "_requests.txt");
	//ARRIVATOQUI
}

void newMessageHandler(int n){
	//per farlo devo metterle globali
	unsigned char* message = takeAMessage();
	send_obj(sock, message, messageLen);
}

void newRequestHandler(int n){
	
}

void handle_logout(int sock){
	//COMPLETARE
}
*/
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


void handle_auth(int sock, struct userStruct* users){
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
	
	//Update online users' list
	//addUsertoList(get_username, users );
	
		

}

void establishDHExhange(int sock, unsigned char* sessionKey){
	//SYMMETRIC SESSION KEY NEGOTIATION BY MEANS OF EPHEMERAL DIFFIE-HELLMAN
	int lim = 0;
	EVP_PKEY* dhPrivateKey = generateDHParams();
	EVP_PKEY* myPrivK;
	EVP_PKEY* DHClientPubK;
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

	printf("QUI\n");
	
}

int main (int argc, const char** argv){
	/*sighandler_t s;
	//Defining the handler that will manage the signal sent by a process to another one to notify the arrive of a new message
	s = signal(signalNewMessage, newMessageHandler);
	if(s == SIG_ERR){
		perror("Error during defining the signal");
		exit(-1);
	}
	s = signal(signalNewRequest, newRequestHandler);
	if(s == SIG_ERR){
		perror("Error during defining the signal");
		exit(-1);
	}*/
    int socket_ascolto; //Socket where our server wait for connections
	printf("Insert password:");
	unsigned char pw[DIM_PASSWORD];
	unsigned char* sessionkey;
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
	//Inizializzo i due set
	FD_ZERO(&master);
	FD_ZERO(&read_ready);
	
	FD_SET(socket_ascolto, &master);	//Add the socket where I wait for connections requests on the main set
	fdmax = socket_ascolto;	
	FD_SET(socket_ascolto, &read_ready);

	//commentato da Matte bool* users = (bool*) mmap(NULL, TOT_USERS, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);	
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
	//initUsers(users);
	/*
	commentato da Matte
	 pthread_mutexattr_t mutexattr;
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
	 rc =pthread_mutex_init(&mutex, &mutexattr);
	 if (rc != 0){
	   perror("pthread_mutex_init");
	   exit(-1);
	  }*/
	    
	
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
						
							int len = receive_len(socket_com);
							unsigned char* command = (unsigned char*) malloc(len);
							if(!command){
								perror("malloc");
								exit(-1);
							}
							receive_obj(socket_com, command, len);
							printf("I have received: %s from %s \n", command, username); 
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
						#pragma optimize("", on)
						   	free(sessionkey);
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
	}
	close(socket_ascolto);

	exit(-1);
}
