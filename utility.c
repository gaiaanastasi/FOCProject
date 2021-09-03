//UTILITY FILE
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <cstring>
#include <stdbool.h>

#define TOT_USERS 2

int receive_len (int socket_com){
//Receive the length of the message via socket
	ssize_t no_err;
	uint32_t dim_network;
	no_err = recv(socket_com, &dim_network, sizeof(uint32_t), MSG_WAITALL);
	if (no_err < sizeof(uint32_t) || no_err == -1 ){
		perror("recv message length");
		exit(-1);		
	}
	int dim_buf = ntohl(dim_network);
	if( dim_buf <= 0){
		perror("recv message length not acceptable");
		exit(-1);
	}
	return dim_buf;
}

void receive_obj (int socket_com, char* buf, int dim_buf){
//Receive the message via socket
	ssize_t no_err = recv(socket_com, buf, dim_buf, MSG_WAITALL);
	
	if (no_err < dim_buf || no_err == -1){
		perror("recv");
		exit(-1);		
	}
}


void send_obj (int sock, char* buf, size_t len){		
//Send the message via socket
	uint32_t dim_obj = htonl(len);
	ssize_t no_err;
	//send the message length first
	no_err = send (sock, &dim_obj, sizeof(uint32_t), 0);		
	if(no_err == -1 || no_err < sizeof(uint32_t)){
		perror("send lunghezza dell'oggetto");	
		exit(-1);
	}
	//send object
	no_err = send(sock,(void*)buf,len, 0 );
	if(no_err == -1){
		perror("send");	
		exit(-1);
	}
}

//return a portion of the src array
//l'array ritornato è una porzione di src che va da src[start] a src[end - 1]
void extract_data_from_array(unsigned char* dest, unsigned char* src, int start, int end){
	int i,j;
	if(start < 0 || end < 0 || start > end || src == NULL || dest == NULL){
		perror("wrong parameters");
		dest = NULL;
		return;
	}
	j = 0;
	if (end < INT_MIN + start){
		perror("integer overflow");
		dest = NULL;
		return;
	}
	for(i = start; i < end; i++){
		dest[j] = src[i];
		j++;
	}
}

//return if the sum between the two elements doesn't cause overflow
void sumControl(int a, int b){
	if (a > INT_MAX - b){
		perror("integer overflow");
		exit(-1);
	}
	
}

void subControlInt(int a, int b){
	if (a > b){
		perror("integer overflow");
		exit(-1);
	}
	
}

//concate two sources in one other array
void concat2Elements(unsigned char* dest, unsigned char* src1, unsigned char* src2, int len1, int len2){
	sumControl(len1, len2);
	memset(dest, 0, len1 + len2);
	memcpy(dest, src1, len1);
	memcpy(dest + len1, src2, len2);
}


