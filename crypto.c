#include <openssl/rand.h>

#define DIM_NONCE 16

//function that generate a nonce of DIM_NONCE bit
void generateNonce(char* nonce){
	if(RAND_poll() != 1)
		perror("error occured during RAND_poll()");
	if(RAND_bytes(nonce, DIM_NONCE) != 1)
		perror("error occured during generation of the nonce");
	printf("the nonce has been generated\n");
}

bool verifySignature (char* signed_msg){
	//SISTEMARE
	return false;
}
