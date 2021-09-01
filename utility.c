//UTILITY FILE
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>

int receive_len (int socket_com){
//Funzione per ricevere dimensione del messaggio da ricevere via socket
	ssize_t no_err;
	uint32_t dim_network;
	no_err = recv(socket_com, &dim_network, sizeof(uint32_t), MSG_WAITALL);
	if (no_err < sizeof(uint32_t) || no_err == -1 ){
		perror("recv message length");
		exit(-1);		
	}
	//Ricevo la dimensione del messaggio
	int dim_buf = ntohl(dim_network);
	if( dim_buf <= 0){
		perror("recv message length not acceptable");
		exit(-1);
	}
	return dim_buf;
}

void receive_obj (int socket_com, char* buf, int dim_buf){
	ssize_t no_err = recv(socket_com, buf, dim_buf, MSG_WAITALL);
	
	if (no_err < dim_buf || no_err == -1){
		perror("recv");
		exit(-1);		
	}
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
	no_err = send(sock,(void*)buf,len, 0 );
	if(no_err == -1){
		perror("send");	
		exit(-1);
	}
}

//return a portion of the src array
//l'array ritornato è una porzione di src che va da src[start] a src[end - 1]
void extract_data_from_array(char* dest, char* src, int start, int end){
	int i,j;
	if(start < 0 || end < 0 || start > end || src == NULL || dest == NULL){
		perror("wrong parameters");
		return;
	}
	j = 0;
	if (end < INT_MIN + start){
		perror("integer overflow");
		return;
	}
	for(i = start; i < end; i++){
		dest[j] = src[i];
		j++;
	}
}

//return true if the sum between the two elements doesn't cause overflow
bool sumControl(int a, int b){
	if (a > INT_MAX - b){
		perror("integer overflow");
		exit(-1);
	}
}