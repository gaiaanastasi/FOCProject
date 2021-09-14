//CLIENT

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <unistd.h>
#include "crypto.c"

const int port_address = 4242;
const char ip_address[16] = "127.0.0.1";
const int MAX_LEN_MESSAGE = 10000;
int counter_send_server = 0;
int counter_recv_server = 0;
int counter_send_client = 0;
int counter_recv_client = 0;


//Function that control the communication with another client. If requestingClient is true, it means that the client that called the function
//has requested the communication and so it has to start it by generating and sending the nonce. If it is false, it has to wait the nonce itself.
//It returns true if the user wanted to leave the conversation, false otherwise
bool communication_with_other_client(int sock, unsigned char* serializedPubKey, int keyLen, EVP_PKEY* myPrivK, bool requestingClient, char* clientUsername, unsigned char* serverSimKey){
	unsigned char clientNonce[DIM_NONCE];		//fresh nonce used for communication with the other client
	unsigned char myNonce[DIM_NONCE];
	EVP_PKEY* clientPubK;						//Public key of the client with wich I want to talk
	EVP_PKEY* dhPrivateKey;			//Diffie-Hellman private key
	EVP_PKEY* dhClientPubK;			//Diffie-Hellman public key sent by the other client
	unsigned char* opBuffer; 		//buffer used for different operations
	int dimOpBuffer = 0;			//length of the content of opBuffer	
	unsigned char* receive;
	int recv_len = 0;
	unsigned char* message_send;
	int send_len = 0;
	unsigned char* plaintext;
	int pt_len;						//length of the plaintext
	unsigned char* message;	//message that has to be sent
	int msg_len = 0;				//length of the message to be sent
	unsigned char* simKey;			//simmetric key used by the two clients
	unsigned char* charPointer;		//generic char pointer 
	unsigned char* signature;
	int signatureLen;
	fd_set readSet;					//fd set that will contain the socket and the stdin, in order to know if a request is arrived or if the user has typed something

	clientPubK = deserializePublicKey(serializedPubKey, keyLen);
	if(clientPubK == NULL){
		perror("Error during deserialization of the public key");
		exit(-1);
	}
	generateNonce(myNonce);
	if(requestingClient){
		message = symmetricEncryption(myNonce, DIM_NONCE, serverSimKey, &msg_len, &counter_send_server);
		if(!message){
			perror("Error during symmetric encryption");
			exit(-1);
		}
		send_obj(sock, message, msg_len);
		free(message);
	}
	else{
		msg_len = receive_len(sock);
		message = (unsigned char*) malloc(msg_len);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		receive_obj(sock, message, msg_len);
		plaintext = symmetricDecription(message, msg_len, &pt_len, serverSimKey, &counter_recv_server);
		if(!plaintext){
			perror("Error during symmetric encryption");
			exit(-1);
		}
		memcpy(clientNonce, plaintext, DIM_NONCE);
		free(plaintext);
		free(message);
	}
	dhPrivateKey = generateDHParams();
	if(requestingClient){
		//I have to wait until the nonce of the other client arrives 
		signatureLen = receive_len(sock);
		recv_len = receive_len(sock);
		receive = (unsigned char*) malloc(recv_len);
		if(receive == NULL){
			perror("Error during malloc()");
			exit(-1);
		}
		receive_obj(sock, receive, recv_len);
		opBuffer = symmetricDecription(receive, recv_len, &dimOpBuffer, serverSimKey, &counter_recv_server);
		if(!opBuffer){
			perror("Error during symmetric encryption");
			exit(-1);
		}
		free(receive);
		//opBuffer contains a message { <myNonce> | <client_nonce> | <serializedDHPublicKey> | <signature> } 
		/*plaintext = from_DigEnv_to_PlainText(opBuffer, dimOpBuffer, &pt_len, myPrivK);
		if(plaintext == NULL){
			perror("Error during the asymmetric decription");
			exit(-1);
		}*/
		signature = (unsigned char*) malloc(signatureLen);
		if(!signature){
			perror("Error during malloc()");
			exit(-1);
		}
		extract_data_from_array(signature, opBuffer, dimOpBuffer - signatureLen, dimOpBuffer);
		subControlInt(dimOpBuffer, signatureLen);
		pt_len = dimOpBuffer - signatureLen;
		plaintext = (unsigned char*) malloc(pt_len);
		if(!plaintext){
			perror("Error during malloc()");
			exit(-1);
		}
		extract_data_from_array(plaintext, opBuffer, 0, pt_len);
		if(!verifySignature(signature, plaintext, signatureLen, pt_len, clientPubK)){
			perror("signature");
			exit(-1);
		}
		sumControl(DIM_NONCE, DIM_NONCE);
		extract_data_from_array(clientNonce, plaintext, DIM_NONCE, DIM_NONCE + DIM_NONCE);
		receive = (unsigned char*) malloc(DIM_NONCE);
		if(!receive){
			perror("Error during malloc()");
			exit(-1);
		}
		extract_data_from_array(receive, plaintext, 0, DIM_NONCE);
		if(memcmp(receive, myNonce, DIM_NONCE) != 0){
			perror("The nonces are different");
			exit(-1);
		}
		free(receive);
		free(opBuffer);
		subControlInt(pt_len, DIM_NONCE);
		subControlInt(pt_len - DIM_NONCE, DIM_NONCE);
		dimOpBuffer = pt_len - DIM_NONCE - DIM_NONCE;
		opBuffer = (unsigned char*) malloc(dimOpBuffer);
		if(opBuffer == NULL){
			perror("Error during malloc()");
			exit(-1);
		}
		sumControl(DIM_NONCE, DIM_NONCE);
		extract_data_from_array(opBuffer, plaintext, DIM_NONCE + DIM_NONCE, pt_len);
		dhClientPubK = deserializePublicKey(opBuffer, dimOpBuffer);
		if(dhClientPubK == NULL){
			perror("Error occured by deserializing the DH public key");
			exit(-1);
		}
		free(opBuffer);
		free(plaintext);
		//creation of the message that must be sent to the client. Formatted as { <client_nonce> | <myNonce> | <DHPubkey> | <signature> }
		opBuffer = serializePublicKey(dhPrivateKey, &dimOpBuffer);
		if(opBuffer == NULL){
			perror("Error during the serialization of the key");
			exit(-1);
		}
		sumControl(DIM_NONCE, dimOpBuffer);
		sumControl(DIM_NONCE + dimOpBuffer, DIM_NONCE);
		pt_len = DIM_NONCE + dimOpBuffer + DIM_NONCE;
		plaintext = (unsigned char*) malloc(pt_len);
		if(!plaintext){
			perror("Error during malloc()");
			exit(-1);
		}
		memcpy(plaintext, clientNonce, DIM_NONCE);
		concatElements(plaintext, myNonce, DIM_NONCE, DIM_NONCE);
		sumControl(DIM_NONCE,DIM_NONCE);
		concatElements(plaintext, opBuffer, DIM_NONCE + DIM_NONCE, dimOpBuffer);
		free(opBuffer);
		dimOpBuffer = 0;
		opBuffer = (unsigned char*) malloc(EVP_PKEY_size(myPrivK));
		if(!opBuffer){
			perror("Error during malloc()");
			exit(-1);
		}
		signatureFunction(plaintext, pt_len, opBuffer, &dimOpBuffer, myPrivK);
		sumControl(dimOpBuffer, pt_len);
		msg_len = dimOpBuffer + pt_len);
		message = (unsigned char*) malloc(dimOpBuffer + pt_len);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		concat2Elements(message, plaintext, opBuffer, pt_len, dimOpBuffer);
		//message contains { <clientNonce> | <myNonce> | <DHPublicKey> | <signature> }
		message_send = symmetricEncryption(message, msg_len, serverSimKey, &send_len, &counter_send_server);
		if(!message_send){
			perror("Error during symmetric encryption");
			exit(-1);
		}
		send_int(dimOpBuffer);
		send_obj(sock, message_send, send_len);
		free(opBuffer);
		free(message_send);
		free(message);
	} 
	else{
		//I have to send the message first
		//creation of the message that must be sent to the client. Formatted as { <client_nonce> | <myNonce> | <DHPubkey> }
		opBuffer = serializePublicKey(dhPrivateKey, &dimOpBuffer);
		if(opBuffer == NULL){
			perror("Error during the serialization of the key");
			exit(-1);
		}
		sumControl(DIM_NONCE, dimOpBuffer);
		sumControl(DIM_NONCE + dimOpBuffer, DIM_NONCE);
		pt_len = DIM_NONCE + dimOpBuffer + DIM_NONCE;
		plaintext = (unsigned char*) malloc(pt_len);
		if(!plaintext){
			perror("Error during malloc()");
			exit(-1);
		}
		memcpy(plaintext, clientNonce, DIM_NONCE);
		concatElements(plaintext, myNonce, DIM_NONCE, DIM_NONCE);
		concatElements(plaintext, opBuffer, DIM_NONCE + DIM_NONCE, dimOpBuffer);
		free(opBuffer);
		dimOpBuffer = 0;
		/*opBuffer = from_pt_to_DigEnv(plaintext, pt_len, clientPubK, &dimOpBuffer);
		if(opBuffer == NULL){
			perror("Error during asymmetric encryption");
			exit(-1);
		}
		//I created a message { <client_nonce> | <myNonce> | <serializedDHPublicKey> } encrypted by means of the client public key*/
		opBuffer = (unsigned char*) malloc(EVP_PKEY_size(myPrivK));
		if(!opBuffer){
			perror("Error during malloc()");
			exit(-1);
		}
		signatureFunction(plaintext, pt_len, opBuffer, &dimOpBuffer, myPrivK);
		sumControl(dimOpBuffer, pt_len);
		msg_len = dimOpBuffer + pt_len);
		message = (unsigned char*) malloc(dimOpBuffer + pt_len);
		if(!message){
			perror("Error during malloc()");
			exit(-1);
		}
		concat2Elements(message, plaintext, opBuffer, pt_len, dimOpBuffer);
		//message contains { <clientNonce> | <myNonce> | <DHPublicKey> | <signature> }
		message_send = symmetricEncryption(message, msg_len, serverSimKey, &send_len, &counter_send_server);
		if(!message_send){
			perror("Error during symmetric encryption");
			exit(-1);
		}
		send_int(sock, dimOpBuffer);
		send_obj(sock, message_send, send_len);
		free(opBuffer);
		free(message_send);
		signatureLen = receive_len(sock);
		recv_len = receive_len(sock);
		receive = (unsigned char*) malloc(recv_len);
		if(receive == NULL){
			perror("Error during malloc()");
			exit(-1);
		}
		receive_obj(sock, receive, recv_len);
		opBuffer = symmetricDecription(receive, recv_len, &dimOpBuffer, serverSimKey, &counter_recv_server);
		if(!opBuffer){
			perror("Error during symmetric encryption");
			exit(-1);
		}
		signature = (unsigned char*) malloc(signatureLen);
		if(!signature){
			perror("Error during malloc()");
			exit(-1);
		}
		extract_data_from_array(signature, opBuffer, dimOpBuffer - signatureLen, dimOpBuffer);
		subControlInt(dimOpBuffer, signatureLen);
		pt_len = dimOpBuffer - signatureLen;
		plaintext = (unsigned char*) malloc(pt_len);
		if(!plaintext){
			perror("Error during malloc()");
			exit(-1);
		}
		extract_data_from_array(plaintext, opBuffer, 0, pt_len);
		if(!verifySignature(signature, plaintext, signatureLen, pt_len, clientPubK)){
			perror("signature");
			exit(-1);
		}
		//opBuffer contains a message { <myNonce> | <client_nonce> | <serializedDHPublicKey> | <signature>}
		/*plaintext = from_DigEnv_to_PlainText(opBuffer, dimOpBuffer, &pt_len, myPrivK);
		if(plaintext == NULL){
			perror("Error during the asymmetric decription");
			exit(-1);
		}*/
		free(receive);
		free(opBuffer);
		dimOpBuffer = DIM_NONCE;
		opBuffer = (unsigned char*) malloc(dimOpBuffer);
		if(opBuffer == NULL){
			perror("Error during malloc()");
			exit(-1);
		}
		extract_data_from_array(opBuffer, plaintext, 0, DIM_NONCE);
		if(memcmp(opBuffer, myNonce, DIM_NONCE) != 0){
			perror("The two nonces are not equal");
			exit(-1);
		}
		extract_data_from_array(opBuffer, plaintext, DIM_NONCE, DIM_NONCE + DIM_NONCE);
		if(memcmp(opBuffer, clientNonce, DIM_NONCE) != 0){
			perror("The two nonces are not equal");
			exit(-1);
		}
		free(opBuffer);
		dimOpBuffer = pt_len - DIM_NONCE - DIM_NONCE;
		opBuffer = (unsigned char*) malloc(dimOpBuffer);
		if(opBuffer == NULL){
			perror("Error during malloc()");
			exit(-1);
		}
		extract_data_from_array(opBuffer, plaintext, DIM_NONCE + DIM_NONCE, pt_len);
		dhClientPubK = deserializePublicKey(opBuffer, dimOpBuffer);
		if(dhClientPubK == NULL){
			perror("Error occured by deserializing the DH public key");
			exit(-1);
		}
		free(opBuffer);
		free(plaintext);
	}
	simKey = symmetricKeyDerivation_for_aes_128_gcm(dhPrivateKey, dhClientPubK);
	if(simKey == NULL){
		perror("Error during the generation of the shared simmetric key");
		exit(-1);
	}

	printf("\nNow you are ready to talk with %s. You can leave the conversation whenever you want by logging you out by typing '<exit>'\n\n", clientUsername);

	//the user can both wait for a new message or type its own message to send it to the other user
	while(1){
		FD_ZERO(&readSet);		//cleaning the set
		FD_SET(0, &readSet);		//stdin added to the set
		FD_SET(sock, &readSet);		//sock added to the set
		int ret = select(sock + 1, &readSet, NULL, NULL, NULL);
		if(ret < 0){
			perror("Error during select()\n");
			exit(-1);
		}
		if(FD_ISSET(0, &readSet)){
			//the user has typed something
			pt_len = MAX_LEN_MESSAGE;
			plaintext = (unsigned char*) malloc(pt_len);
			if(plaintext == NULL){
				perror("Error during malloc()");
				exit(-1);
			}
			if(fgets(plaintext, MAX_LEN_MESSAGE, stdin) == NULL){
				perror("Error during the input of the message");
				exit(-1);
			}
			charPointer = strchr(plaintext, '\n');
			if(charPointer)
				*charPointer = '\0';

			//control if the user want to leave the conversation
			if(strcmp(plaintext, "<exit>") == 0){
				//the first time I send the message to the other client, to notify him that I'm leaving the chat
				IncControl(strlen("<exit>"));
				pt_len = strlen("<exit>") + 1;
				message = symmetricEncryption(plaintext, pt_len, simKey, &msg_len, &counter_send_client);
				if(message == NULL){
					perror("Error during encryption of the message");
					exit(-1);
				}
				opBuffer = symmetricEncryption(message, msg_len, serverSimKey, &dimOpBuffer, &counter_send_server);
				if(!opBuffer){
					perror("Error during symmetric encryption");
					exit(-1);
				}
				send_obj(sock, opBuffer, dimOpBuffer);
				free(message);
				free(opBuffer);
				msg_len = 0;

				//The second time I send the message to the server, to notify my log-off
				message = symmetricEncryption(plaintext, pt_len, serverSimKey, &msg_len, &counter_send_server);
				if(message == NULL){
					perror("Error during encryption of the message");
					exit(-1);
				}
				send_obj(sock, message, msg_len);
				free(message);
				free(plaintext);
				return true;
			}

			//encryption and sending of the message
			IncControl(strlen(plaintext));
			pt_len = strlen(plaintext) + 1;
			message = symmetricEncryption(plaintext, pt_len, simKey, &msg_len, &counter_send_client);
			if(message == NULL){
				perror("Error during the encryption of the message");
				exit(-1);
			}
			opBuffer = symmetricEncryption(message, msg_len, serverSimKey, &dimOpBuffer, &counter_send_server);
			if(!opBuffer){
				perror("Error during symmetric encryption");
				exit(-1);
			}
			send_obj(sock, opBuffer, dimOpBuffer);
			free(message);
			free(opBuffer);
			free(plaintext);
			msg_len = 0;
			pt_len = 0;
		} 
		else if(FD_ISSET(sock, &readSet)){
			//the user received a new message
			msg_len = receive_len(sock);
			message = (unsigned char*) malloc(msg_len);
			if(message == NULL){
				perror("Error during malloc()");
				exit(-1);
			}
			receive_obj(sock, message, msg_len);
			opBuffer = symmetricDecription(message, msg_len, &dimOpBuffer, serverSimKey, &counter_recv_server);
			if(!opBuffer){
				perror("Error during symmetric decryption");
				exit(-1);
			}
			plaintext = symmetricDecription(opBuffer, dimOpBuffer, &pt_len, simKey, &counter_recv_client);
			if(plaintext == NULL){
				perror("Error during the decription of the message");
				exit(-1);
			}
			if(pt_len > MAX_LEN_MESSAGE){
				perror("The received message is too long");
				exit(-1);
			}
			//control if the other client has logged off
			if(strcmp(plaintext, "<exit>") == 0){
				printf("\n%s has logged off\n", clientUsername);
				free(plaintext);
				free(message);
				break;
			}
			//printf("\n");
			printf("%s: ", clientUsername);
			printf("%s\n", plaintext);
			free(plaintext);
			free(message);
			free(opBuffer);
			pt_len = msg_len = 0;
		}
	}
	EVP_PKEY_free(clientPubK);
	EVP_PKEY_free(dhPrivateKey);
	EVP_PKEY_free(dhClientPubK);
	free(simKey);
	return false;
}

int main(int argc, const char** argv){

	int sock;				//socket identifier
    struct sockaddr_in srv_addr;
	int ret;				//it will contain different integer return values (used for checking)
	size_t command;			//command typed by the user
	unsigned char* message_recv;
	int recv_len = 0;		//length of the received message
	unsigned char* message_send;
	int send_len = 0;		//length of the message to be sent
	unsigned char* plaintext;
	int pt_len = 0;			//length of the plaintext
	unsigned char* serverSymmetricKey;
	unsigned char serverNonce[DIM_NONCE];		//fresh nonce used for communication with the server
	unsigned char myNonce[DIM_NONCE];
	X509* serverCertificate = NULL;
	X509* CACertificate = NULL;
	unsigned char* opBuffer; 		//buffer used for different operations
	int dimOpBuffer = 0;	//length of the content of opBuffer	
	X509_STORE* certStore = NULL;	//certificate store of the client
	EVP_PKEY* serverPubK = NULL;	//public key of the server
	EVP_PKEY* dhPrivateKey = NULL;	//private key generated by DH algorithm
	EVP_PKEY* myPrivK = NULL;		//private key of the user
	EVP_PKEY* DHServerPubK = NULL;	//Diffie-Hellman public key of the server
	char fileName[64];				//it will contain different names for different files
	char username[DIM_USERNAME];		//username to log in
	char password[DIM_PASSWORD];		//password to find the private key
	char* charPointer;				//generic pointer used in different parts
	unsigned char* signature;			//it will contain the signature
	int signatureLen;			//len of the signature
	FILE* file = NULL;			//generic file pointer used in different parts of the code
	fd_set readFdSet;			//fd set that will contain the socket and the stdin, in order to know if a request is arrived or if the user has typed something
	int continueWhile = 1;		//it remains equal to 1 until the user decide to log out 


	
	//log in of the user
	memset(username, 0, DIM_USERNAME);
	printf("Insert your username:\t");
	if(fgets(username, DIM_USERNAME, stdin) == NULL){
		perror("Error during the reading from stdin\n");
		exit(-1);
	}
	charPointer = strchr(username, '\n');
	if(charPointer)
		*charPointer = '\0';
	printf("Insert your password:\t");
	getPassword(password);
	
	
	//socket creation and instantiation
	sock = socket(AF_INET, SOCK_STREAM, 0);
	memset(&srv_addr, 0, sizeof(srv_addr)); // Pulizia
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(port_address);
	inet_pton(AF_INET, ip_address, &srv_addr.sin_addr);
    ret = connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
	if(ret < 0){
		perror("An error occured during the connection phase \n");
		exit(-1);
	}

	
	
	//LOADING PRIVATE KEY
	strncpy(fileName, "keys/", DIR_SIZE);
	subControlInt(DIR_SIZE,1);
	fileName[DIR_SIZE-1] = '\0';
	strncat(fileName, username, DIM_USERNAME);
	strncat(fileName, "_privkey.pem", DIM_SUFFIX_FILE_PRIVKEY);
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

	//CERTIFICATE STORE CREATION
	IncControl(strlen("certificates/CA_cert.pem""certificates/CA_cert.pem"));
	strncpy(fileName, "certificates/CA_cert.pem", strlen("certificates/CA_cert.pem")+1);
	fileName[strlen("certificates/CA_cert.pem")] = '\0';
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
	ret = X509_STORE_add_cert(certStore, CACertificate);
	if(ret != 1){
		perror("Error during the adding of a certificate\n");
		exit(-1);
	}
	

	//AUTHENTICATION WITH THE SERVER
	//RECEIVING THE NONCE AND THE CERTIFICATE
	recv_len = receive_len(sock);
	message_recv = (unsigned char*) malloc(recv_len);
	if(!message_recv){
		perror("malloc");
		exit(-1);
	}
	//MESSAGE STRUCTURE: <serverNonce> | <certificate> 
	receive_obj(sock, message_recv, recv_len);
	extract_data_from_array(serverNonce, message_recv, 0, DIM_NONCE);
	if(serverNonce == NULL){
		perror("Error during the extraction of the nonce of the server\n");
		exit(-1);
	}
	
	dimOpBuffer = recv_len - DIM_NONCE;
	opBuffer = (unsigned char*) malloc((dimOpBuffer));
	if(!opBuffer){
		perror("malloc");
		exit(-1);
	}
	extract_data_from_array(opBuffer, message_recv, DIM_NONCE, recv_len);	//opBuffer will contain the serialized certificate of the server
	if(opBuffer == NULL){
		perror("Error during the extraction of the certificate of the server\n");
		exit(-1);
	}
	charPointer = opBuffer;
	serverCertificate = d2i_X509(NULL, (const unsigned char**)&charPointer, dimOpBuffer);
	
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

	//SYMMETRIC SESSION KEY NEGOTIATION BY MEANS OF EPHEMERAL DIFFIE-HELLMAN
	dhPrivateKey = generateDHParams();
	//SERIALIZATION OF THE DH PUBLIC KEY
	opBuffer = serializePublicKey(dhPrivateKey, &dimOpBuffer);
	if(opBuffer == NULL){
		perror("Error during serialization of the DH public key\n");
		exit(-1);
	}
	//opBuffer contains the serialized DH public key

	//CREATION OF THE MESSAGE THAT HAS TO BE SENT TO THE SERVER (DH PUB KEY EXCHANGE)
	sumControl(DIM_NONCE, DIM_NONCE);
	sumControl(DIM_NONCE + DIM_NONCE, dimOpBuffer);
	pt_len = DIM_NONCE + DIM_NONCE + dimOpBuffer;
	plaintext = (unsigned char*) malloc(pt_len);
	if(!plaintext){
		perror("Error during malloc()");
		exit(-1);
	}
	generateNonce(myNonce);
	memcpy(plaintext, myNonce, DIM_NONCE);
	concatElements(plaintext, serverNonce, DIM_NONCE, DIM_NONCE);
	concatElements(plaintext, opBuffer, DIM_NONCE + DIM_NONCE, dimOpBuffer);
	//now I have to sign the message
	signature = (unsigned char*) malloc(EVP_PKEY_size(myPrivK));
	if(signature == NULL){
		perror("Error during malloc()");
		exit(-1);
	}
	signatureFunction(plaintext, pt_len, signature, &signatureLen, myPrivK);
	free(opBuffer);
	sumControl(pt_len, signatureLen);
	dimOpBuffer = pt_len + signatureLen;
	opBuffer = (unsigned char*) malloc(dimOpBuffer);
	if(!opBuffer){
		perror("Error during malloc()");
		exit(-1);
	}
	concat2Elements(opBuffer, plaintext, signature, pt_len, signatureLen);
	charPointer = from_pt_to_DigEnv(opBuffer, dimOpBuffer, serverPubK, &ret);
	//Now charPointer contains the result of the symmetric encryption and ret its length
	if(charPointer == NULL){
		perror("Error during asymmetric encryption");
		exit(-1);
	}
	//opBuffer already freed by from_pt_to_DigEnv
	free(plaintext);
	free(signature);
	sumControl(DIM_USERNAME, ret);
	send_len = DIM_USERNAME + ret;
	message_send = (unsigned char*) malloc(send_len);
	if(!message_send){
		perror("Error during malloc()");
		exit(-1);
	}
	concat2Elements(message_send, username, charPointer, DIM_USERNAME, ret);
	//At first I have to send the length of the signature
	send_int(sock, signatureLen);
	send_obj(sock, message_send, send_len);
	free(message_send);
	free(charPointer);
	
	//RECEIVING DH PUBLIC KEY OF THE SERVER
	signatureLen = receive_len(sock);
	recv_len = receive_len(sock);
	message_recv = (unsigned char*) malloc(recv_len);
	if(message_recv == NULL){
		perror("Error during malloc()");
		exit(-1);
	}
	receive_obj(sock, message_recv, recv_len);

	//asymmetric decryption
	plaintext = from_DigEnv_to_PlainText(message_recv, recv_len, &pt_len, myPrivK);
	if(plaintext == NULL){
		perror("Error during the asimmetric decryption\n");
		exit(-1);
	}
	free(message_recv);
	//plaintext would have the format { <serverNonce> | <clientNonce> | <serverPubKeyDH> | <signature> }
	//check for the nonces
	dimOpBuffer = DIM_NONCE;
	opBuffer = (unsigned char*) malloc(dimOpBuffer);	//it'll contain the nonce sent in the last message
	if(!opBuffer){
		perror("malloc");
		exit(-1);
	}
	sumControl (DIM_NONCE, DIM_NONCE);
	extract_data_from_array(opBuffer, plaintext, DIM_NONCE, DIM_NONCE + DIM_NONCE);
	if(memcmp(opBuffer, myNonce, DIM_NONCE) != 0){
		perror("The two nonces are different\n");
		exit(-1);
	}
	extract_data_from_array(opBuffer, plaintext, 0, DIM_NONCE);
	if(memcmp(opBuffer, serverNonce, DIM_NONCE) != 0){
		perror("The two nonces are different\n");
		exit(-1);
	}
	free(opBuffer);
	subControlInt(pt_len, signatureLen);
	dimOpBuffer = pt_len - signatureLen;
	opBuffer = (unsigned char*) malloc(dimOpBuffer);
	signature = (unsigned char*) malloc(signatureLen);
	if(!opBuffer || !signature){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(opBuffer, plaintext, 0, dimOpBuffer);
	extract_data_from_array(signature, plaintext, dimOpBuffer, pt_len);
	//now opBuffer contains the message and signature the signature
	if(!verifySignature(signature, opBuffer, signatureLen, dimOpBuffer, serverPubK)){
		perror("Error in the signature");
		exit(-1);
	}
	free(opBuffer);
	free(signature);
	//deserialization of the server DH public key
	sumControl(DIM_NONCE + DIM_NONCE, signatureLen);
	subControlInt(pt_len, DIM_NONCE+DIM_NONCE+signatureLen);
	dimOpBuffer = pt_len - (DIM_NONCE + DIM_NONCE + signatureLen);
	opBuffer = (unsigned char*) malloc(dimOpBuffer);	//it'll contain the serialization of the DH public key of the server
	if(opBuffer == NULL){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(opBuffer, plaintext, DIM_NONCE+DIM_NONCE, pt_len - signatureLen);
	DHServerPubK = deserializePublicKey(opBuffer, dimOpBuffer);
	if(DHServerPubK == NULL){
		perror("Error during deserialization of the DH public key\n");
		exit(-1);
	}
	serverSymmetricKey = symmetricKeyDerivation_for_aes_128_gcm(dhPrivateKey, DHServerPubK);
	if(serverSymmetricKey == NULL){
		perror("Error during the derivation of the shared simmetric key");
		exit(-1);
	}

	//now that we have a fresh symmetric key, some informations are useless
	EVP_PKEY_free(serverPubK);
	EVP_PKEY_free(DHServerPubK);
	EVP_PKEY_free(dhPrivateKey);
	free(opBuffer);
	dimOpBuffer = 0;
	free(plaintext);

	printf("Hi! This is a secure messaging system\n");

	while(continueWhile){
		//("%s", commandMessage);
		printf("\nType:\n(1) to see who's online\n(2) to send a request to talk\n(3) to log out\n");
		printf("What do you want to do?\n");
		FD_ZERO(&readFdSet);		//cleaning the set
		FD_SET(0, &readFdSet);		//stdin added to the set
		FD_SET(sock, &readFdSet);		//sock added to the set
		ret = select(sock + 1, &readFdSet, NULL, NULL, NULL);
		if(ret < 0){
			perror("Error during select()\n");
			exit(-1);
		}
		if(FD_ISSET(0, &readFdSet)){
			//the user has typed something
			if(scanf("%1ld", &command) != 1){
				perror("scanf function has read a wrong number of items");
				exit(-1);
			}
			while(getchar() != '\n');		//cleaning the stdin buffer
			switch(command){
				case 1:		//online people
					sumControl(strlen("online_people"), 1);
					pt_len = strlen("online_people") + 1;
					plaintext = (unsigned char*) malloc(pt_len);
					if(plaintext == NULL){
						perror("Error during malloc()");
						exit(-1);
					}
					IncControl(strlen("online_people"));
					strncpy(plaintext, "online_people", strlen("online_people")+1);
					plaintext[strlen("online_people")]='\0';
					message_send = symmetricEncryption(plaintext, pt_len, serverSymmetricKey, &send_len, &counter_send_server);
					if(!message_send){
						perror("Error during symmetric encryption");
						exit(-1);
					}
					free(plaintext);
					send_obj(sock, message_send, send_len);
					recv_len = receive_len(sock);
					message_recv = (unsigned char*) malloc(recv_len);
					if(message_recv == NULL){
						perror("Error during malloc()");
						exit(-1);
					}
					receive_obj(sock, message_recv, recv_len);
					plaintext = symmetricDecription(message_recv, recv_len, &pt_len, serverSymmetricKey, &counter_recv_server);
					if(!plaintext){
						perror("Error during symmetric encryption");
						exit(-1);
					}
					printf("%s", plaintext);
					free(message_recv);
					free(message_send);
					free(plaintext);
					send_len = 0;
					recv_len = 0;
					break;

				case 2:		//request to talk
					printf("who do you want to send the request to?\n");
					opBuffer = (unsigned char*) malloc(DIM_USERNAME);
					if(opBuffer == NULL){
						perror("Error during malloc()");
						exit(-1);
					}
					if(fgets(opBuffer, DIM_USERNAME, stdin) == NULL){
						perror("Error during the fgets()");
						exit(-1);
					}
					charPointer = strchr(opBuffer, '\n');
					if(charPointer)
						*charPointer = '\0';
					if(strcmp(opBuffer, username) == 0){
						printf("\nyou can not speak with yourself!\n");
						free(opBuffer);
						break;
					}
					IncControl(strlen("request"));
					sumControl(DIM_USERNAME, strlen("request") + 1);
					pt_len = DIM_USERNAME + strlen("request") + 1;
					plaintext = (unsigned char*) malloc(pt_len);
					if(plaintext == NULL){
						perror("Error during malloc()");
						exit(-1);
					}
					concat2Elements(plaintext, opBuffer, "request", DIM_USERNAME, strlen("request") + 1);
					//message to be sent has the format { <requested_username> | "request" }
					message_send = symmetricEncryption(plaintext, pt_len, serverSymmetricKey, &send_len, &counter_send_server);
					if(message_send == NULL){
						perror("Error during the encryption of the message");
						exit(-1);
					}
					send_obj(sock, message_send, send_len);
					send_len = 0;
					free(message_send);
					#pragma optimize("", off);
						memset(plaintext, 0, pt_len);
					#pragma optimize("", on);
					free(plaintext);
					pt_len = 0;
					recv_len = receive_len(sock);
					message_recv = (unsigned char*) malloc(recv_len);
					if(message_recv == NULL){
						perror("Error during malloc()");
						exit(-1);
					}
					receive_obj(sock, message_recv, recv_len);
					plaintext = symmetricDecription(message_recv, recv_len, &pt_len, serverSymmetricKey, &counter_recv_server);
					if(plaintext == NULL){
						perror("Error during the symmetric decription");
						exit(-1);
					}
					if(strcmp(plaintext, "refused") == 0){
						printf("\nYour request to talk with %s has been refused\n", opBuffer);
						free(opBuffer);
						free(plaintext);
						free(message_recv);
						dimOpBuffer = 0;
						break;
					}
					else if(strcmp(plaintext, "wrong_format") == 0){
						printf("\nYour request to talk with %s has not been sent because you have typed a username that does not exist\n", opBuffer);
						free(opBuffer);
						free(plaintext);
						free(message_recv);
						dimOpBuffer = 0;
						break;
					}
					else if(strcmp(plaintext, "busy") == 0){
						printf("\n%s is already busy in another conversation, keep trying later\n", opBuffer);
						free(opBuffer);
						free(plaintext);
						free(message_recv);
						dimOpBuffer = 0;
						break;
					}
					else if(strcmp(plaintext, "not_online") == 0){
						printf("\n%s is not online\n", opBuffer);
						free(opBuffer);
						free(plaintext);
						free(message_recv);
						dimOpBuffer = 0;
						break;
					}

					//request accepted, the plaintext is the serialized public key of the client
					if(communication_with_other_client(sock, plaintext, pt_len, myPrivK, true, opBuffer, serverSymmetricKey)){
						continueWhile = 0;
					}
					free(opBuffer);
					dimOpBuffer = 0;
					free(plaintext);
					pt_len = 0;
					free(message_recv);
					break;

				case 3:		//logout
					printf("\nLogging out\n");
					IncControl(strlen("logout"));
					pt_len = strlen("logout") + 1;
					plaintext = (unsigned char*) malloc(pt_len);
					if(plaintext == NULL){
						perror("Error during malloc()");
						exit(-1);
					}
					IncControl(strlen("logout"));
					strncpy(plaintext, "logout", strlen("logout")+1);
					plaintext[strlen("logout")]='\0';
					message_send = symmetricEncryption(plaintext, pt_len, serverSymmetricKey, &send_len);
					if(!message_send){
						perror("Error during symmetric encryption");
						exit(-1);
					}
					free(plaintext);
					send_obj(sock, message_send, send_len);
					continueWhile = 0;
					free(message_send);
					break;
				default:
					perror("The inserted command is not valid\n");
					break;
			}
		}
		else if(FD_ISSET(sock, &readFdSet)){
			//a request to talk has arrived
			recv_len = receive_len(sock);
			message_recv = (unsigned char*) malloc(recv_len);
			if(message_recv == NULL){
				perror("Error during malloc()");
				exit(-1);
			}
			receive_obj(sock, message_recv, recv_len);
			//the message is encrypted by means of the symmetric key used by server and client
			plaintext = symmetricDecription(message_recv, recv_len, &pt_len, serverSymmetricKey, &counter_recv_server);
			//the plaintext would have the format { <username that sent the request> | <"request"> }
			if(plaintext == NULL){
				perror("Error during the symmetric decription");
				exit(-1);
			}
			if(pt_len <= DIM_USERNAME){
				perror("Unrecognized format of the received message");
				exit(-1);
			}
			dimOpBuffer = pt_len - DIM_USERNAME;
			opBuffer = (unsigned char*) malloc(dimOpBuffer);
			if(opBuffer == NULL){
				perror("Error during malloc()");
				exit(-1);
			}
			extract_data_from_array(opBuffer, plaintext, DIM_USERNAME, pt_len);
			if(strcmp(opBuffer, "request") != 0){
				perror("Unrecognized format of the received message");
				exit(-1);
			}
			free(opBuffer);
			dimOpBuffer = DIM_USERNAME;
			opBuffer = (unsigned char*) malloc(dimOpBuffer);
			if(opBuffer == NULL){
				perror("Error during malloc()");
				exit(-1);
			}
			extract_data_from_array(opBuffer, plaintext, 0, DIM_USERNAME);
			free(plaintext);
			pt_len = 0;
			printf("\nYou received a request to talk from %s. Type 'y' if you want to accept or 'n' if you want to refuse it\n", opBuffer);
			sumControl(DIM_USERNAME, 2);
			pt_len = DIM_USERNAME + 2;
			plaintext = (unsigned char*) malloc(pt_len);
			if(plaintext == NULL){
				perror("Error during malloc()");
				exit(-1);
			}
			if(fgets(plaintext, 3, stdin) == NULL){
				perror("Error during fgets()");
				exit(-1);
			}
			charPointer = strchr(plaintext, '\n');
			if(charPointer)
				*charPointer = '\0';
			concatElements(plaintext, opBuffer, 2, dimOpBuffer);
			message_send = symmetricEncryption(plaintext, pt_len, serverSymmetricKey, &send_len);
			if(message_send == NULL){
				perror("Error during the encryption of the message");
				exit(-1);
			}
			//send the message formatted like { <"y"/"n"> | <username that sent the request> }
			send_obj(sock, message_send, send_len);
			//I can use strcmp with plaintext because it contains for sure the '\0' character in position plaintext[1]
			free(message_send);
			free(message_recv);
			if(strcmp(plaintext, "y") == 0){
				//request accepted
				printf("\nYou have accepted the request to talk with %s\n", opBuffer);
				recv_len = receive_len(sock);
				message_recv = (unsigned char*) malloc(recv_len);
				if(message_recv == NULL){
					perror("Error during malloc()");
					exit(-1);
				}
				receive_obj(sock, message_recv, recv_len);
				//the message sent by the server contains the public key of the other client, encrypted by means of the simmetric key used by server and client
				plaintext = symmetricDecription(message_recv, recv_len, &pt_len, serverSymmetricKey, &counter_recv_server);
				if(plaintext == NULL){
					perror("Error during symmetric decription");
					exit(-1);
				}
				if(communication_with_other_client(sock, plaintext, pt_len, myPrivK, false, opBuffer, serverSymmetricKey))
					continueWhile = 0;
				free(plaintext);
				free(opBuffer);
				free(message_recv);
			}
			else{
				printf("\nYou have rejected the request to talk with %s\n", opBuffer);
				free(opBuffer);
			}
		}
	}
	free(serverSymmetricKey);
	EVP_PKEY_free(myPrivK);
	X509_STORE_free(certStore);
	close(sock);
	printf("\nBye Bye!\n");
	return 0;
}
