//CLIENT

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "crypto.c"
#include "utility.c"

const int port_address = 4242;
const char ip_address[16] = "127.0.0.1"
const char welcomeMessage[256] = "Hi! This is a secure messaging system \n Type: \n (1) to see who's online \n (2) to send a request to talk (3) to log out\n\n What do you want to do? ";
const int DIM_USERNAME = 32;
const int DIM_PASSWORD = 32;

int main(int argc, const char** argv){
	int socket;
	int ret;				//it will contain different integer return values (used for checking)
	size_t command;			//command typed by the user
	char* message_recv;
	int recv_len = 0;		//length of the received message
	char* message_send;
	int send_len = 0;		//length of the message to be sent
	char* ciphertext;		//result of the encryption of the message that has to be sent
	int cpt_len = 0;		//length of the cyphertext
	char* plaintext;
	int pt_len = 0;
	char serverNonce[DIM_NONCE];
	X509* serverCertificate = NULL;
	X509* CACertificate = NULL;
	char* opBuffer; 		//buffer used for different operations
	char* encrypted_key = NULL;	//encrypted key when we use asymmetric encryption
	int encrypted_key_len;
	char* iv = NULL;		//Initialization vector
	int iv_len;
	int dimOpBuffer = 0;	//length of the content of opBuffer	
	X509_STORE* certStore = NULL;	//certificate store of the client
	EVP_PKEY* serverPubK = NULL;	//public key of the server
	EVP_PKEY* dhPrivateKey = NULL;	//private key generated by DH algorithm
	EVP_PKEY* myPrivK = NULL;		//private key of the user
	EVP_PKEY* myPubK = NULL;		//public key of the user
	EVP_PKEY* DHparams = NULL;			//DH parameters
	EVP_PKEY_CTX* DHctx = NULL;		//DH context
	EVP_CIPHER* cipher = NULL;		//cipher currently used
	char fileName[64];				//it will contain different names for different files
	char username[DIM_USERNAME];		//username to log in
	char password[DIM_PASSWORD];		//password to find the private key
	char* charPointer;				//generic pointer used in different parts
	char* signature;			//it will contain the signature
	int signatureLen;			//len of the signature
	FILE* file = NULL;			//generic file pointer used in different parts of the code

	//socket creation and instantiation
	socket = socket(AF_INET, SOCK_STREAM, 0);
	memset(&srv_addr, 0, sizeof(srv_addr)); // Pulizia
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(atoi(port_address));
	inet_pton(AF_INET, ip_address, &srv_addr.sin_addr);
    ret = connect(socket, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
	if(ret < 0){
		perror("An error occured during the connection phase \n");
		exit(-1);
	}

	//log in of the user
	memset(username, 0, DIM_USERNAME);
	printf("Insert your username:\t");
	if(fgets(username, DIM_USERNAME, stdin) == NULL){
		perror("Error during the reading from stdin\n");
		exit(-1);
	}
	charPointer = strchr(username, '\n');
	if(charPointer)
		*p = '\0';
	printf("Insert your password:\t");
	if(fgets(password, DIM_PASSWORD, stdin) == NULL){
		perror("Error during the reading from stdin\n");
		exit(-1);
	}
	charPointer = strchr(password, '\n');
	if(charPointer)
		*p = '\0';
	
	//LOADING PRIVATE KEY
	strcpy(fileName, "keys/");
	strcat(fileName, username);
	strcat(fileName, "_privkey.pem");
	file = fopen(fileName, "r");
	if(file == NULL){
		perror("Error during the opening of a file\n");
		exit(-1);
	}
	myPrivK = PEM_read_PrivateKey(file, NULL, NULL, password);
	if(myPrivK == NULL){
		perror("Error during the loading of the private key, maybe wrong password?\n");
		exit(-1);
	}
	fclose(file);

	//LOADING PUBLIC KEY
	strcpy(fieName, "keys/");
	strcat(fileName, username);
	strcat(fileName, "_pubkey.pem");
	file = fopen(fileName, "r");
	if(file == NULL){
		perror("Error during the opening of a file\n");
		exit(-1);
	}
	myPubK = PEM_read_PUBKEY(file, NULL, NULL, NULL);
	if(myPubK == NULL){
		perror("Error during the loading of the public key\n");
		exit(-1);
	}
	fclose(file);

	//CERTIFICATE STORE CREATION
	strcpy(fileName, "certificates/CA_cert.pem");
	file = fopen(fileName, "r");
	if(file == NULL){
		perror("Error during opening of the file CA_cert.pem\n");
		exit(-1);
	}
	CACertificate = PEM_read_X509(file, NULL, NULL, NULL);
	fclose(file);
	if(CACertificate == NULL){
		perror("Error during the extraction of the certificate from the file\n");
		exit(-1);
	}
	certStore = X509_STORE_new();
	if(certStore == NULL){
		perror("Error during the creation of the store\n");
		exit(-1);
	}
	ret = x509_STORE_add_cert(certStore, CACertificate);
	if(ret != 1){
		perror("Error during the adding of a certificate\n");
		exit(-1);
	}

	//AUTHENTICATION WITH THE SERVER
	recv_len = receive_len(socket);
	message_recv = (char*) malloc(recv_len * sizeof(char));
	receive_obj(socket, message_recv, recv_len);
	serverNonce = (char*) malloc((DIM_NONCE) * sizeof(char));
	extract_data_from_array(serverNonce, message_recv, 0, DIM_NONCE);
	if(serverNonce == NULL){
		perror("Error during the extraction of the nonce of the server\n");
		exit(-1);
	}
	dimOpBuffer = recv_len - DIM_NONCE;
	opBuffer = (char*) malloc((dimOpBuffer) * sizeof(char));
	extract_data_from_array(opBuffer, message_recv, DIM_NONCE, recv_len);	//opBuffer will contain the serialized certificate of the server
	if(opBuffer == NULL){
		perror("Error during the extraction of the certificate of the server\n");
		exit(-1);
	}
	serverCertificate = d2i_X509(NULL, (const unsigned char**)&opBuffer, dimOpBuffer);
	if(serverCertificate == NULL){
		perror("Error during deserialization of the certificate of the server\n");
		exit(-1);
	}

	//now that I have the certificate, its serialization is useless
	free(opBuffer);
	dimOpBuffer = 0;
	//certificate verification
	if(!verifyCertificate(certStore, serverCertificate)){
		perror("Error during verification of the server certificate\n");
		exit(-1);
	}

	serverPubK = X509_get_pubkey(serverCertificate);
	if(serverPubK == NULL){
		perror("Error during the extraction of the public key of the server from its certificate\n");
		exit(-1);
	}
	//now that I have the public key of the server, the certificate is useless
	X509_free(serverCertificate);
	free(message_recv);
	recv_len = 0;

	//CREATION OF THE MESSAGE THAT HAS TO BE SENT TO THE SERVER (CLIENT AUTHENTICATION)
	dimOpBuffer = DIM_NONCE + DIM_USERNAME;
	opBuffer = (char*) malloc(dimOpBuffer * sizeof(char));
	concat2Elements(opBuffer, serverNonce, username, DIM_NONCE, DIM_USERNAME);
	signature = (char*)malloc(EVP_PKEY_size(myPrivK));
	signatureFunction(opBuffer, dimOpBuffer, signature, &signatureLen, myPrivK);
	send_len = dimOpBuffer + signatureLen;
	message_send = (char*) malloc(send_len);
	concat2Elements(message_send, opBuffer, signature, dimOpBuffer, signatureLen);

	send_obj(socket, message_send, send_len);
	free(message_send);
	send_len = 0;

	//SYMMETRIC SESSION KEY NEGOTIATION BY MEANS OF EPHEMERAL DIFFIE-HELLMAN
	DHparams = EVP_PKEY_new();
	if(DHparams == NULL){
		perror("Error during instantiation of DH parameters\n");
		exit(-1);
	}
	generateDHParams(DHparams);
	DHctx = EVP_PKEY_CTX_new(DHparams, NULL);
	if(DHctx == NULL){
		perror("Error during the allocation of the context for DH key generation\n");
		exit(-1);
	}
	ret = EVP_PKEY_keygen_init(DHctx);
	if(ret != 1){
		perror("Error during initialization of the context for DH key generation\n");
		exit(-1);
	}
	ret = EVP_PKEY_keygen(DHctx, &dhPrivateKey);
	if(ret != 1){
		perror("Error during generation of Diffie-Hellman key\n");
		exit(-1);
	}	
	EVP_PKEY_CTX_free(DHctx);
	EVP_PKEY_free(DHparams);

	//SERIALIZATION OF THE DH PUBLIC KEY
	myBio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(myBio, dhPrivateKey);
	opBuffer = NULL;
	dimOpBuffer = BIO_get_mem_data(myBio, &opBuffer);
	opBuffer = (char*) malloc(dimOpBuffer * sizeof(char));
	BIO_read(myBio, (void*) opBuffer, dimOpBuffer);
	BIO_free(myBio);
	//opBuffer contains the DH public key
	//CREATION OF THE MESSAGE THAT HAS TO BE SENT TO THE SERVER (DH PUB KEY EXCHANGE)
	sumControl(DIM_NONCE, dimOpBuffer);
	pt_len = DIM_NONCE + dimOpBuffer;
	plaintext = (char*) malloc(pt_len);
	concat2Elements(plaintext, serverNonce, opBuffer, DIM_NONCE, dimOpBuffer);
	//delete public key from opBuffer
#pragma optimize("", off)
   	memset(opBuffer, 0, dimOpBuffer);
#pragma optimize("", on)
	free(opBuffer);
	dimOpBuffer = 0;

	//asymmetric encryption
	cipher = EVP_aes_128_cbc();
	encrypted_key_len = EVP_PKEY_size(serverPubK);
	iv_len = EVP_CIPHER_iv_length(cipher);
	encrypted_key = (char*) malloc(encrypted_key_len);
	iv = (char*) malloc(iv_len);
	sumControl(pt_len, EVP_CIPHER_block_size(cipher));
	ciphertext = (char*) malloc(pt_len + EVP_CIPHER_block_size(cipher));
	if(!iv || !encrypted_key || !ciphertext){
		perror("Error during malloc\n");
		exit(-1);
	}
	if(!createDigitalEnvelope(cipher, plaintext, pt_len, encrypted_key, encrypted_key_len, iv, iv_len, ciphertext, &cpt_len, serverPubK)){
		perror("Error during creation of the digital envelope\n");
		exit(-1);
	}
	sumControl(encrypted_key_len, iv_len);
	dimOpBuffer = encrypted_key_len + iv_len;
	opBuffer = (char*) malloc(dimOpBuffer);
	concat2Elements(opBuffer, encrypted_key, iv, encrypted_key_len, iv_len);
	sumControl(dimOpBuffer, cpt_len);
	send_len = dimOpBuffer + cpt_len;
	message_send = (char*) malloc(send_len);
	concat2Elements(message_send, opBuffer, cpt, dimOpBuffer, cpt_len);
	send_obj(socket, message_send, send_len);

	free(message_send);
	free(iv);
	free(encrypted_key);

	//now that we have a symmetric key, some informations are useless
	EVP_PKEY_free(serverPubK);
	free(serverNonce);

	printf("%s", welcomeMessage);
	while(1){
		if(scanf("%d", &command) =! 1){
			perror("scanf function has read a wrong number of items \n");
			exit(-1);
		}
		switch(command){
			case 1:		//online people
				break;
			case 2:		//request to talk
				break;
			case 3:		//logging out
				break;

		}
	}
	EVP_PKEY_free(myPrivK);
	EVP_PKEY_free(myPubK);
	X509_STORE_free(certStore);
	return 0;
}