//UTILITY FILE

char* receive_obj (int socket_com){
//Funzione per ricevere stringhe
	ssize_t no_err;
	uint32_t dim_network;
	no_err = recv(socket_com, &dim_network, sizeof(uint32_t), MSG_WAITALL);
	if (no_err < sizeof(uint32_t) || no_err == -1 ){
		perror("recv lunghezza del messaggio:");
		exit(0);		
	}
	//Ricevo la dimensione della stringa
	int dim_buf = ntohl(dim_network);
	
	//Ricezione stringa
	char* buf = malloc(dim_buf+1); 
	if(!buf){
		perror("malloc");
		exit(0);
	}
	no_err = recv(socket_com, buf, dim_buf+1, MSG_WAITALL);
	
	if (no_err < dim_buf+1 || no_err == -1){
		perror("recv");
		exit(0);		
	}
	return buf;
}


void send_obj (int sock, char* buf, size_t len){		
//Funzione utilizzata per inviare oggetti via socket
	uint32_t dim_obj = htonl(len);
	ssize_t no_err;
	//Invio al socket la lunghezza della stringa
	no_err = send (sock, &dim_obj, sizeof(uint32_t), 0);		
	if(no_err == -1 || no_err < sizeof(uint32_t)){
		perror("send lunghezza dell'oggetto");	
		exit(-1);
	}
	//Invio al socket la stringa vera e propria
	no_err = send(sock,(void*)buf,len+1, 0 );
	if(no_err == -1){
		perror("send");	
		exit(-1);
	}
}