//UTILITY FILE
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <termios.h>

#define TOT_USERS 2
#define DIM_PASSWORD 32

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

void receive_obj (int socket_com, unsigned char* buf, int dim_buf){
//Receive the message via socket
	ssize_t no_err = recv(socket_com, buf, dim_buf, MSG_WAITALL);
	
	if (no_err < dim_buf || no_err == -1){
		perror("recv");
		exit(-1);		
	}
}


void send_obj (int sock, unsigned char* buf, size_t len){		
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
	/*for(i = start; i < end; i++){
		dest[j] = src[i];
		j++;
	}*/
	
	memset(dest, 0, end-start);
	memcpy(dest, src+start, end-start);
}

//return if the sum between the two elements doesn't cause overflow
void sumControl(int a, int b){
	if (a > INT_MAX - b){
		perror("integer overflow");
		exit(-1);
	}
	
}

void subControlInt(int a, int b){
	if(a <0 || b<0){
		perror("integer overflow");
		exit(-1);
	}

	if (b>a){
		perror("integer overflow");
		exit(-1);
	}
	
}

bool comparisonUnsignedChar (unsigned char* src1, unsigned char* src2, int len){
	for (int i = 0; i<len; i++){
		if(src1[i] != src2[i]) return false;
	}
	return true;
}

//concate two sources in one other array
void concat2Elements(unsigned char* dest, unsigned char* src1, unsigned char* src2, int len1, int len2){
	if(!src1 || !src2){
		printf("Invalid input\n");
		exit(-1);
	}
	sumControl(len1, len2);
	memset(dest, 0, len1 + len2);
	memcpy(dest, src1, len1);
	memcpy(dest + len1, src2, len2);
}

//concat src at the end of dest
void concat2Elements(unsigned char* dest, unsigned char* src, int destLen, int srcLen){
	sumControl(destLen, srcLen);
	memcpy(dest + destLen, src, srcLen);
}

void getPassword(unsigned char* password){
	struct termios old, new;
	int nread;

	/* Turn echoing off and fail if we can't. */
	if (tcgetattr (fileno (stdin), &old) != 0){
		perror("Error while getting the password");
		exit(-1);
	}
	new = old;
	new.c_lflag &= ~ECHO;
	if (tcsetattr (fileno (stdin), TCSAFLUSH, &new) != 0){
		perror("Error while getting the password");
		exit(-1);
	}
		

	/* Read the password. */
	if(fgets(password, DIM_PASSWORD, stdin) == NULL){
		perror("Error during the reading from stdin\n");
		exit(-1);
	}
	char* charPointer = strchr(password, '\n');
	if(charPointer)
		*charPointer = '\0';

	/* Restore terminal. */
	if(tcsetattr (fileno (stdin), TCSAFLUSH, &old)){
		perror("Error while restoring the terminal");
		exit(-1);
	}
	printf("\n");

}



