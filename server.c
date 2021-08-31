//CLIENT

#include <sys/socket.h>
#include "utility.c"
#include "crypto.c"


void get_online_user (int sock){

}


void handle_send_request(int sock){

}

void handle_logout(int sock){

}

X509* getServerCertificate (){
	/*///GET THE CERTIFICATE FROM PEM FILE
	X509* cert;
	FILE* file = fopen("server.pem", "r");
	if(!file){
		perror("fopen");
		exit(0);
	}
	cert = PEM_read_X509(file, NULL, NULL, NULL);
	if(!cert) {
		perror("certificate not found");
		exit(0);
	}
	fclose(file); 
	return cert;
	*/
}


int handle_auth(int sock){
	//Server retrieves his certificate and generate a nonce
	char myNonce[DIM_NONCE];
	generateNonce(myNonce);
	
	/*X509* cert = getServerCertificate();

	//Send a certification over a socket

	unsigned_char* cert_buf = NULL;
	unsigned int cert_size = id2_X509(cert, &cert_buf);
	if(cert_size < 0) {
		perror("certificate size error");
		exit(0);
	}

	//Generate msg
	
	send_obj(sock, cert_buf, cert_size);
	send_obj(sock, myNonce, DIM_NONCE);
	OPENSSL_free(cert_buf);

	client_cert = receive(sock);
	signed_nonce = receive(sock);
	bool ret =verifyClientIdentity(client_cert, signed_nonce);

	*/

}

int main (int argc, const char** argv){
    int socket_ascolto; //Socket where our server wait for connections
				
	socket_ascolto = socket(AF_INET, SOCK_STREAM, 0);
	
	if(socket_ascolto == -1){
		perror("Socket");
		exit(0);
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
		exit(0);	
	}
    //socket_ascolto is the socket used for receiving connection requests
	ret = listen(socket_ascolto, 10);
	if (ret == -1){
		perror("listen");
		exit(0);
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
						exit(0);
					}
					FD_SET(socket_com, &master);	//Add the new socket to the main set
					if (socket_com > socket_ascolto) fdmax = socket_com;
					handle_auth(sock_com);
					
				}
				else{	//It's not socket_ascolto, it's another one
					pid_t pid = fork();
					if (pid== -1){
						perror ("fork");
						exit(0);
					}
					else if (pid == 0){		//I am in the child process
						close(socket_ascolto);
						
						
						
						while(1){
						
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
						close(i);
						FD_CLR(i, &master);		//Delete the socket from the main set
						exit(0);
					}
					//Parent process
					close(i);	//Closure socket
					FD_CLR(i, &master);		//Delete the socket from the main set
					
				}
			}
		}
	}
	close(socket_ascolto);

	exit(0);
}