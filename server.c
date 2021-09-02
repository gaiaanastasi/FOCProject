//CLIENT

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "utility.c"
#include "crypto.c"
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#define DIM_SUFFIX_FILE_PUBKEY 12
#define DIM_SUFFIX_FILE_PRIVKEY 13
#define DIM_PASSWORD 32
#define DIR_SIZE 14
#define DIR "/keys/public/"
#define DIM_NONCE 16
#define DIM_USERNAME 32


unsigned char myNonce[DIM_NONCE];


void updateOnlineUserList (unsigned chat* username){
	//COMPLETARE
}

void get_online_user (int sock){
	//COMPLETARE
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
	FILE* file = fopen("server_cert.pem", "r");
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


void handle_auth(int sock){
	//Server retrieves his certificate and generate a nonce
	//char myNonce[DIM_NONCE];
	generateNonce(myNonce);
	
	X509* cert = getServerCertificate();

	//Send a certification over a socket

	uunsigned char* cert_buf = NULL;
	unsigned int cert_size = i2d_X509(cert, &cert_buf);
	if(cert_size < 0) {
		perror("certificate size error");
		exit(-1);
	}

	//Generate msg
	if (DIM_NONCE == INT_MAX){
		perror("increment overflow");
		exit(-1);
	}
	sumControl (cert_size, DIM_NONCE + 1);
	
	size_t size_msg = cert_size + DIM_NONCE + 1;
	unsigned char msg[size_msg];
	concat2Elements(msg, myNonce, cert_buf, DIM_NONCE, cert_size);
	
	OPENSSL_free(cert_buf);
	send_obj(sock, msg, size_msg);
	
	//Receive signed nonce from client
	int signed_size = receive_len(sock);
	sumControl(signed_size, 1);
	unsigned char signed_msg[signed_size];
	receive_obj(sock, signed_msg, signed_size); 
	
	//Get the nonce and the username from the message I have received
	unsigned char get_username[DIM_USERNAME];
	extract_data_from_array(signed_msg, get_username, 0, DIM_USERNAME);
	sumControl (signed_size, DIM_USERNAME);
	
	int signed_nonce_size = signed_size - DIM_USERNAME;
	unsigned char signed_nonce[signed_nonce_size];
	extract_data_from_array(signed_msg, signed_nonce, DIM_USERNAME, signed_size);
	
	//Get the public key from pem file
	EVP_PKEY* pubkey;
	sumControl(DIR_SIZE, DIM_SUFFIX_FILE_PUBKEY);
	sumControl(DIR_USERNAME, (DIM_SUFFIX_FILE_PUBKEY-DIR_SIZE));
	int name_size = DIM_USERNAME + DIM_SUFFIX_FILE_PUBKEY + DIR_SIZE;
	unsigned char namefile[name_size];
	int lim = DIR_SIZE -1;
	strcat ((char*)namefile, (char*)DIR, lim);
	lim= DIM_USERNAME -1;
	strcat ((char*)namefile, (char*)get_username, lim);
	lim= DIM_SUFFIX_FILE_PUBKEY-1;
	strcat ((char*)namefile, (char*)"pubkey.pem", lim);
	FILE* file = fopen(namefile, "r");
	if(!file){
		perror("Specified file doesn't exists");
		exit(-1);
	}
	pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
	if (!pubkey){
		perror("Pubkey not found");
		exit(-1);
	}
	fclose(file);
	
	//Signature verification
	bool ret =verifySignature(signed_msg, myNonce, signed_nonce_size, DIM_NONCE, pubkey);
	if (ret){
		printf("%s authentication succeded!", get_username);

	}
	else {
		perror("signature verify failure");
		exit(-1);
	}
	EVP_PKEY_free(pubkey);
	
	//Update online users' list
	updateOnlineUserList(get_username);
	
		

}

int main (int argc, const char** argv){
    int socket_ascolto; //Socket where our server wait for connections
				
	socket_ascolto = socket(AF_INET, SOCK_STREAM, 0);
	
	if(socket_ascolto == -1){
		perror("Socket");
		exit(-1);
	}
	else printf("Apertura del socket di ascolto \n");
	struct sockaddr_in indirizzo_server;
	//Parameters for server socket
	memset(&indirizzo_server, 0, sizeof(indirizzo_server));		//Clean 
	int porta = atoi(argv[1]);
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

	printf("Server in ascolto \n");
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
					handle_auth(socket_com);
					
				}
				else{	//It's not socket_ascolto, it's another one
					pid_t pid = fork();
					if (pid== -1){
						perror ("fork");
						exit(-1);
					}
					else if (pid == 0){		//I am in the child process
						close(socket_ascolto);
						
						//EDHKE
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
						
						//send_obj (/*finire*/);
						free(mbio);
						
						
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
						#pragma optimize("", off)
						   	memset(session_key, 0, session_key_size);
						#pragma optimize("", on)
						   	free(session_key);
						
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
