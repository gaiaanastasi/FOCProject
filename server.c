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


#define DIM_SUFFIX_FILE_PUBKEY 12
#define DIM_SUFFIX_FILE_PRIVKEY 13
#define DIM_PASSWORD 32
#define DIR_SIZE 6
#define DIR "keys/"
#define DIM_NONCE 16
#define DIM_USERNAME 32

char* server_port = "4242";



unsigned char myNonce[DIM_NONCE];
pthread_mutex_t mutex;

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
		strncpy((char*)ret, "matteo", strlen("matteo"));
	}
	if(i==1) {
		ret = (unsigned char*) malloc (strlen("gaia")+1);
		strncpy((char*)ret, "gaia", strlen("gaia"));
	}
	else {
		ret = (unsigned char*) malloc (strlen("")+1);
		strncpy((char*)ret, "", strlen(""));
	}
	return ret;

}


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
	
	
}

unsigned int getNumberOfOnlineUsers(bool* online_users){
	unsigned int tot = 0;
	for (unsigned int i=0; i<TOT_USERS; i++){
		if(online_users[i]) tot++;
	}
	return tot;
}

void getOnlineUser (int sock, bool* online_users){
	//Get the total number of active user
	unsigned int tot = getNumberOfOnlineUsers(online_users);
	if (tot == 0) {
		perror("error in getNumberOfOnlineUsers");
		exit(-1);
	}
	
	unsigned char* online[tot];
	int last = 0;
	
	for (unsigned int i=0; i<TOT_USERS; i++){
		//Get the username of each online user
		unsigned char* mapping = mappingIntToUser(i);
		if(online_users) {
			//Store it in an array
			online[last] = mapping;
			last++;
		}
		#pragma optimize("", off)
	   	memset(mapping, 0, strlen((char*)mapping)+1);
		#pragma optimize("", on)
	   	free(mapping);
			
	}
	//send_obj(sock, online, tot); DEVO FARE UNA SEND PER MANDARE VETTORI DI STRINGHE
	
	
}


void handle_send_request(int sock){
	//COMPLETARE
}

void handle_logout(int sock){
	//COMPLETARE
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


void handle_auth(int sock, bool* users_online){
	//Server retrieves his certificate and generate a nonce
	//char myNonce[DIM_NONCE];
	printf("In handle_auth\n");
	generateNonce(myNonce);
	//printf("My nonce=%s\n", myNonce); 
	
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
	printf("Get signed nonce by username\n");
	
	//Get the nonce and the username from the message I have received
	unsigned char get_username[DIM_USERNAME];
	//Get username
	extract_data_from_array(get_username, signed_msg, 0, DIM_USERNAME);
	sumControl(DIM_USERNAME, DIM_NONCE);
	int nonce_part = DIM_NONCE + DIM_USERNAME;
	unsigned char signed_nonce[DIM_NONCE];
	//Get nonce
	extract_data_from_array(signed_nonce, signed_msg,DIM_USERNAME, nonce_part);
	subControlInt(signed_size, nonce_part);
	int signature_len = signed_size - nonce_part;
	unsigned char* signature = (unsigned char*) malloc(signature_len);
	if(!signature){
		perror("malloc");
		exit(-1);
	}
	//Get digital signature
	extract_data_from_array(signature, signed_msg, nonce_part, signed_size);
	
	//Get the public key from pem file
	EVP_PKEY* pubkey;
	sumControl(DIR_SIZE, DIM_SUFFIX_FILE_PUBKEY);
	sumControl(DIM_USERNAME, (DIM_SUFFIX_FILE_PUBKEY+DIR_SIZE));
	int name_size = DIM_USERNAME + DIM_SUFFIX_FILE_PUBKEY + DIR_SIZE;
	char fileName[name_size];
	int lim = DIR_SIZE; 
	//Get file name
	strncpy(fileName, (char*)DIR, lim );
	lim = DIM_USERNAME; 
	strncat(fileName, (char*)get_username, lim );
	lim = DIM_SUFFIX_FILE_PUBKEY;
	strncat(fileName, "_pubkey.pem", lim);
	//printf("%s\n", fileName);
	FILE* file = fopen(fileName, "r");
	if(!file){
		perror("fopen");
		exit(-1);
	}
	
	//Retrive client's public key
	pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
	if (!pubkey){
		perror("Pubkey not found");
		exit(-1);
	}
	fclose(file);

	//Signature verification
	bool ret =verifySignature(signature, myNonce, signature_len, DIM_NONCE, pubkey);
	//Comparison between myNonce and the nonce the client has sent me back
	bool ret2 = comparisonUnsignedChar(myNonce, signed_nonce, DIM_NONCE);
	if (ret && ret2){
		printf("%s authentication succeded!", get_username);
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
	
	//Update online users' list
	//addUsertoList(get_username, users_online );
	
		

}

int main (int argc, const char** argv){
    int socket_ascolto; //Socket where our server wait for connections
				
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

	bool* users_online = (bool*) mmap(NULL, TOT_USERS, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);	
	/*int fd = open(argv[1], O_RDONLY);
	if(fd==-1){
		perror("Open fail");
		exit(-1);
	}*/
	
	if (users_online == MAP_FAILED){
		perror("MAP_FAILED");
		exit(-1);
	}
	
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
	  }
	    
	
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
						
					handle_auth(socket_com, users_online);
					
					
				}
				else{	//It's not socket_ascolto, it's another one
					pid_t pid = fork();
					if (pid== -1){
						perror ("fork");
						exit(-1);
					}
					else if (pid == 0){		//I am in the child process
						close(socket_ascolto);
						
						
						
						/*//EDHKE
						EVP_PKEY* params = EVP_PKEY_new();
						if(params == NULL){
							perror("Error during instantiation of DH parameters\n");
							exit(-1);
						}
						generateDHParams(params);
						
						EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(params, NULL);
						if(ctx == NULL){
							perror("Error during the allocation of the context for DH key generation\n");
							exit(-1);
						}
						EVP_PKEY* my_prvkey = NULL;
						EVP_PKEY_keygen_init(ctx);
						if(ret != 1){
							perror("Error during initialization of the context for DH key generation\n");
							exit(-1);
						}
						EVP_PKEY_keygen(ctx, &my_prvkey);
						if(ret != 1){
							perror("Error during generation of Diffie-Hellman key\n");
							exit(-1);
						}	
						EVP_PKEY_CTX_free(ctx);
						
						//Serialize the key to send that over socket
						BIO* mbio = BIO_new(BIO_s_mem());
						if (!mbio){
							perror("Error in BIO allocation \n");
							exit(-1);
						} 
						PEM_write_bio_PUBKEY(mbio, my_prvkey);
						char* pubkey_buf = NULL;
						long pubkey_size = BIO_get_mem_data(mbio, &pubkey_buf);
						
						//DEVO CONCATENARCI IL NONCE E CIFRARE CON LA CHIAVE PUBBLICA DEL CLIENT
						
						//send_obj (/*finire*///);
						/*free(mbio);
						
						
						//Receive the response from the client
						int complete_msg_size = (int) receive_len (i);
						char* client_message = (char*) malloc (complete_msg_size);
						receive_obj(i, client_message, complete_msg_size);
						
						//DECIFRO RISPOSTA CON LA CHIAVE PRIVATA SERVER
						
						#pragma optimize("", off)
						   	memset(client_message, 0, complete_msg_size);
						#pragma optimize("", on)
						   	free(client_message);
						/*
						
						if(!checkNonce(myNonce, receiveNonce)){
							perror("The session isn't fresh \n");
						}
						
						mbio = BIO_new (BIO_s_mem());
						if (!mbio){
							perror("Error in BIO allocation \n");
							exit(-1);
						} 
						BIO_write(mbio, client_pubkey, client_key_size);
						EVP_PKEY* client_key = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
						BIO_free(mbio);
						
						//Secret Derivation
						ctx = EVP_PKEY_CTX_new(params, NULL);
						if(ctx == NULL){
							perror("Error during the allocation of the context for DH secret derivation\n");
							exit(-1);
						}
						EVP_PKEY* client_pubkey = NULL;
						EVP_PKEY_derive_init(ctx);
						if(ret != 1){
							perror("Error during initialization of the context for DH key derivation\n");
							exit(-1);
						}
						EVP_PKEY_derive_set_peer(ctx, client_pubkey);
						if(ret != 1){
							perror("Error during derive_set_peer\n");
							exit(-1);
						}	
						unsigned char* session_key;
						size_t secretlen;
						EVP_PKEY_derive(ctx, NULL, &secretlen);
						if(ret != 1){
							perror("Error during derivation of secret length\n");
							exit(-1);
						}
						session_key = (unsigned char*) malloc (secretlen);
						EVP_PKEY_derive(ctx, session_key, &secretlen);
						if(ret != 1){
							perror("Error during derivation of session key\n");
							exit(-1);
						}
						EVP_PKEY_CTX_free(ctx);
						EVP_PKEY_free(my_prvkey);
						EVP_PKEY_free(client_pubkey);
						EVP_PKEY_free(params);*/
						
						/*while(1){
						
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
							
						}*/
						close(i);
						FD_CLR(i, &master);		//Delete the socket from the main set
						exit(-1);
						/*#pragma optimize("", off)
						   	memset(session_key, 0, session_key_size);
						#pragma optimize("", on)
						   	free(session_key);*/
						
					}
					//Parent process
					close(i);	//Closure socket
					FD_CLR(i, &master);		//Delete the socket from the main set
					
				}
			}
		}
	}
	close(socket_ascolto);

	exit(-1);
}
