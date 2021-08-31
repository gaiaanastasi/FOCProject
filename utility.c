//UTILITY FILE

char* receive_obj (int socket_com, int* len){
//Funzione per ricevere oggetti via socket
	ssize_t no_err;
	uint32_t dim_network;
	no_err = recv(socket_com, &dim_network, sizeof(uint32_t), MSG_WAITALL);
	if (no_err < sizeof(uint32_t) || no_err == -1 ){
		perror("recv lunghezza del messaggio:");
		exit(0);		
	}
	//Ricevo la dimensione della 
	int dim_buf = ntohl(dim_network);
	
	//Ricezione 
	char* buf = malloc(dim_buf); 
	if(!buf){
		perror("malloc");
		exit(0);
	}
	no_err = recv(socket_com, buf, dim_buf, MSG_WAITALL);
	
	if (no_err < dim_buf || no_err == -1){
		perror("recv");
		exit(0);		
	}
	*len = dim_buf;
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

//return a portion of the src array
//l'array ritornato è una porzione di src che va da src[start] a src[end - 1]
char* extract_data_from_array(char* src, int start, int end){
	int i,j;
	if(start < 0 || end < 0 || start > end || src == NULL){
		perror("wrong indexes");
		return NULL;
	}
	char* buffer = (char*) malloc((end - start) * sizeof(char));
	j = 0;
	for(i = start; i < end; i++){
		buffer[j] = src[i];
		j++;
	}
}