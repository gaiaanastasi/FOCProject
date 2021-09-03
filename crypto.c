#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "utility.c"
#include <stdbool.h>


#define DIM_NONCE 16
#define DIM_USERNAME 32
#define DIM_SUFFIX_FILE_PUBKEY 12
#define DIM_SUFFIX_FILE_PRIVKEY 13
#define DIM_PASSWORD 32
#define AAD "0000"
#define DIM_TAG 16
#define DIM_IV 12
#define DIM_BLOCK 128
#define DIM_AAD 4

//function that generate a nonce of DIM_NONCE bit
void generateNonce(char* nonce){
	if(RAND_poll() != 1)
		perror("error occured during RAND_poll()");
	if(RAND_bytes((unsigned char*)nonce, DIM_NONCE) != 1)
		perror("error occured during generation of the nonce");
	printf("the nonce has been generated\n");
}



//function that return the store in signature the signature for a given plaintext and in signatureLen its length
void signatureFunction(char* plaintext, int dimpt, char* signature, int* signatureLen, EVP_PKEY* myPrivK){
    EVP_MD_CTX* signCtx = NULL;		//signature context
    int ret = 0;
    signCtx = EVP_MD_CTX_new();
	ret = EVP_SignInit(signCtx, EVP_sha256());
	if(ret == 0){
		perror("Error during signInit()\n");
	}
	//the plaintext is not big, so we can have only one update
	ret = EVP_SignUpdate(signCtx, plaintext, dimpt);
	if(ret == 0){
		perror("Error during signUpdate()\n");
		exit(-1);
	}
	ret = EVP_SignFinal(signCtx, (unsigned char*)signature, (unsigned int*)signatureLen, myPrivK);
	if(ret == 0){
		perror("Error during signFinal()\n");
		exit(-1);
	}
	EVP_MD_CTX_free(signCtx);
    return;
}

//function wthat verifies the signature
bool verifySignature (char* signed_msg,  char* unsigned_msg, int signed_size, int unsigned_size, EVP_PKEY* pubkey){
	
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	EVP_VerifyInit(ctx, EVP_sha256());
	EVP_VerifyUpdate (ctx, unsigned_msg, unsigned_size);
	int ret = EVP_VerifyFinal(ctx, (unsigned char*)signed_msg, signed_size, pubkey);
	if (ret !=1 ){
		perror("authentication error");
		exit(-1);
	}
	EVP_MD_CTX_free(ctx);
	return true;
}

//function that return Diffie-Hellman low level parameters
static DH *get_dh2048(void)
{
    static unsigned char dhp_2048[] = {
        0xAD, 0x19, 0x74, 0xEB, 0xB8, 0x6C, 0xC5, 0xB5, 0x86, 0x4C,
        0x5B, 0x40, 0x8F, 0x58, 0x4A, 0x3A, 0x38, 0x67, 0x09, 0xB6,
        0x08, 0x8F, 0xC7, 0x0A, 0xF7, 0x5F, 0x31, 0xE7, 0x47, 0x7D,
        0x81, 0x46, 0x9D, 0x33, 0x0F, 0x26, 0x40, 0xBD, 0xC2, 0xE2,
        0xC4, 0x14, 0xF2, 0x64, 0x1B, 0xF3, 0x5E, 0x29, 0xD0, 0xD9,
        0x00, 0x9C, 0x9D, 0xE1, 0xE3, 0x68, 0x55, 0x80, 0xF7, 0x8D,
        0x55, 0xBC, 0x0D, 0x42, 0xE6, 0x27, 0x33, 0xEE, 0x93, 0x30,
        0x11, 0xEC, 0x0B, 0xE1, 0x11, 0xF1, 0x9C, 0x2B, 0xDA, 0x26,
        0xF0, 0xD0, 0xCF, 0x15, 0x0D, 0xF5, 0x46, 0xB7, 0x39, 0xDE,
        0x10, 0x64, 0x6C, 0xA3, 0x47, 0xF2, 0xF9, 0x08, 0x20, 0x69,
        0x2F, 0x54, 0xE2, 0xA6, 0xE8, 0x05, 0x74, 0xEA, 0x1B, 0x50,
        0x0B, 0x1A, 0x72, 0xFD, 0xA9, 0x17, 0xA5, 0xA8, 0x77, 0xC2,
        0xEB, 0x13, 0xAB, 0x02, 0xDE, 0x89, 0xE7, 0x0B, 0x04, 0x3C,
        0xB0, 0xEA, 0xE4, 0x71, 0x0B, 0x88, 0x59, 0x2F, 0x78, 0x7D,
        0x73, 0x2F, 0x44, 0x33, 0xC3, 0xAC, 0xEC, 0xD3, 0x0F, 0x8D,
        0x98, 0x39, 0xFD, 0xBA, 0x4F, 0x25, 0xC0, 0xF5, 0x32, 0x5B,
        0x0D, 0xCC, 0xF4, 0x57, 0x9C, 0x19, 0xA3, 0x1A, 0xDF, 0xD0,
        0x29, 0x24, 0xED, 0xEE, 0xC6, 0x0A, 0x98, 0xBC, 0x1B, 0x78,
        0xD4, 0xB3, 0x0B, 0x18, 0xF4, 0x45, 0xE9, 0x29, 0x4E, 0x5E,
        0x17, 0x27, 0x20, 0x6F, 0xA1, 0x37, 0xF7, 0x4D, 0x6E, 0x2E,
        0x36, 0xD1, 0xF9, 0x92, 0x49, 0x9B, 0x3C, 0x6B, 0xB5, 0x83,
        0x77, 0x25, 0xF7, 0xAF, 0x75, 0x4E, 0x52, 0x09, 0x25, 0x6C,
        0x19, 0xD5, 0x7B, 0x80, 0xA1, 0xEC, 0x13, 0x3A, 0x02, 0x7D,
        0xD8, 0xAA, 0xF4, 0x7D, 0x46, 0x81, 0xC3, 0x86, 0x42, 0x7F,
        0x2D, 0x54, 0xCE, 0x77, 0xC0, 0xE4, 0xDC, 0xF6, 0x8D, 0xAB,
        0xCE, 0x31, 0x33, 0xB0, 0xAB, 0xB3
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;
    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}

//function that generates Diffie-Hellman private key
EVP_PKEY* generateDHParams(){
	int ret;
	EVP_PKEY* DHparams;
	EVP_PKEY_CTX* DHctx;
	EVP_PKEY* dhPrivateKey;
	DHparams = EVP_PKEY_new();
	if(DHparams == NULL){
		perror("Error during instantiation of DH parameters\n");
		exit(-1);
	}
	DH* temp = get_dh2048();
	ret = EVP_PKEY_set1_DH(DHparams, temp);
	if(ret != 1){
		perror("Error during the copy of the low level DH parameters\n");
		exit(-1);
	}
	DH_free(temp);

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
	return dhPrivateKey;
}

//returns true if the certificate is verified by means of the store
bool verifyCertificate(X509_STORE* certStore, X509* certificate){
	X509_STORE_CTX* storeCtx = X509_STORE_CTX_new();
	if(storeCtx == NULL){
		perror("Error during the creation of the context for certificate verification\n");
		exit(-1);
	}
	int ret = X509_STORE_CTX_init(storeCtx, certStore, certificate, NULL);
	if(ret != 1){
		perror("Error during the initilization of the certificate-verification context");
		exit(-1);
	}
	ret = X509_verify_cert(storeCtx);
	if(ret != 1){
		perror("The certificate of the server can not be verified\n");
		exit(-1);
	}
	X509_STORE_CTX_free(storeCtx);
	return true;
}

//function that takes a plaintext and returns a message formatted like { <encrypted_key> | <IV> | <ciphertext> } in an asimmetric encryption
unsigned char* from_pt_to_DigEnv(unsigned char* pt, int pt_len, EVP_PKEY* pubkey, int* dimM){
	int ret;
	int dimB = 0;
	unsigned char* encrypted_key;
	unsigned char* iv;
	unsigned char* ciphertext;
	int encrypted_key_len, iv_len, cpt_len;
	unsigned char* buffer = NULL;
	unsigned char* message = NULL;
	int nc = 0;		//bytes encrypted at each chunk
	int nctot = 0;	//total encrypted bytes
	EVP_CIPHER* cipher = EVP_aes_128_cbc();
	encrypted_key_len = EVP_PKEY_size(pubkey);
	iv_len = EVP_CIPHER_iv_length(cipher);
	encrypted_key = (unsigned char*) malloc(encrypted_key_len);
	iv = (unsigned char*) malloc(iv_len);
	sumControl(pt_len, EVP_CIPHER_block_size(cipher));
	ciphertext = (unsigned char*) malloc(pt_len + EVP_CIPHER_block_size(cipher));
	if(!iv || !encrypted_key || !ciphertext)
		return NULL;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL)
		return NULL;
	ret = EVP_SealInit(ctx, cipher, &encrypted_key, &encrypted_key_len, iv, &pubkey, 1);
	if(ret < 0)
		return NULL;
	ret = EVP_SealUpdate(ctx, ciphertext, &nc, pt, pt_len);
	if(ret == 0)
		return NULL;
	nctot += nc;
	ret = EVP_SealFinal(ctx, ciphertext + nctot, &nc);
	if(ret == 0)
		return NULL;
	nctot += nc;
	cpt_len = nctot;

	EVP_CIPHER_CTX_free(ctx);
#pragma optimize("", off)
   	memset(pt, 0, pt_len);
#pragma optimize("", on)
   	free(pt);
	EVP_CIPHER_free(cipher);

	//message constitution
	sumControl(encrypted_key_len, iv_len);
	dimB = encrypted_key_len + iv_len;
	buffer = (unsigned char*) malloc(dimB);
	concat2Elements(buffer, encrypted_key, iv, encrypted_key_len, iv_len);
	sumControl(dimB, cpt_len);
	*dimM = dimB + cpt_len;
	message = (unsigned char*) malloc(dimM);
	concat2Elements(message, buffer, ciphertext, dimB, cpt_len);
	free(iv);
	free(encrypted_key);
	free(ciphertext);
   	return message;
}

/*
//function that store the plaintext, given the ciphertext, the encrypted key and the IV of a digital envelope. It returns false in case of error
bool asymmetricDecryption(EVP_CIPHER* cipher, unsigned char* pt, int* pt_len, unsigned char* encrypted_key, int encrypted_key_len, unsigned char* iv, int iv_len, unsigned char* cpt, int cpt_len, EVP_PKEY* prvKey){
	int ret;
	int nd = 0; 	// bytes decrypted at each chunk
   	int ndtot = 0; 	// total decrypted bytes
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL)
		return false;
	ret = EVP_OpenInit(ctx, cipher, encrypted_key, encrypted_key_len, iv, prvKey);
	if(ret == 0)
		return false;
	ret = EVP_OpenUpdate(ctx, pt, &nd, cpt, cpt_len);
	if(ret == 0)
		return false;
	ndtot += nd;
	ret = EVP_OpenFinal(ctx, pt + ndtot, &nd);
	if(ret == 0)
		return false;
	ndtot += nd;
	*pt_len = ndtot;

	EVP_CIPHER_CTX_free(ctx);
	
	EVP_CIPHER_CTX(ctx);
	return true;
}*/

//subdivide the received message (formatted { <encrypted_key> | <IV> | <ciphertext> }) into the three parts that are needed for the asymmetric decryption
unsigned char* from_DigEnv_to_PlainText(unsigned char* message, int messageLen, int* pt_len, EVP_PKEY* prvKey){
	int ret;
	unsigned char* pt = NULL;
	unsigned char* encrypted_key;
	unsigned char* iv;
	unsigned char* cpt;
	int encrypted_key_len, iv_len, cpt_len;
	int nd = 0; 	// bytes decrypted at each chunk
   	int ndtot = 0; 	// total decrypted bytes
	EVP_CIPHER_CTX* ctx;
	EVP_CIPHER* cipher = EVP_aes_128_cbc();
	encrypted_key_len = EVP_PKEY_size(privKey);
	iv_len = EVP_CIPHER_iv_length(cipher);
	sumControl(encrypted_key_len, iv_len);
	//check for correct format of the encrypted file
	if(recv_len < encrypted_key_len + iv_len)
		return NULL;
	encrypted_key = (unsigned char*) malloc(encrypted_key_len);
	iv = (unsigned char*) malloc(iv_len);
	cpt_len = recv_len - encrypted_key_len - iv_len;	//possible overflow already controlled
	cpt = (unsigned char*) malloc(cpt_len);
	pt = (unsigned char*) malloc(cpt_len);
	if(!iv || !encrypted_key || !cpt || !pt)
		return NULL;
	extract_data_from_array(encrypted_key, message_recv, 0, encrypted_key_len);
	extract_data_from_array(iv, message_recv, encrypted_key_len, iv_len);
	extract_data_from_array(cpt, message_recv, encrypted_key_len + iv_len, cpt_len);
	//decryption
	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL)
		return NULL;
	ret = EVP_OpenInit(ctx, cipher, encrypted_key, encrypted_key_len, iv, prvKey);
	if(ret == 0)
		return NULL;
	ret = EVP_OpenUpdate(ctx, pt, &nd, cpt, cpt_len);
	if(ret == 0)
		return NULL;
	ndtot += nd;
	ret = EVP_OpenFinal(ctx, (pt) + ndtot, &nd);
	if(ret == 0)
		return NULL;
	ndtot += nd;
	*pt_len = ndtot;
	EVP_CIPHER_CTX_free(ctx);
	EVP_CIPHER_free(cipher);
	free(encrypted_key);
	free(iv);
	free(ciphertext);
	return pt;	

}

//function for symmetric encryption
bool symmetricEncryption(unsigned char* pt, int pt_len,  unsigned char* cpt, int* cpt_len, unsigned char* sessionkey){
	
	int ret = 0;
	int read = 0;
	int howmany =0;
	int dim =0;
	unsigned char tag[DIM_TAG];
	unsigned char* iv = (unsigned char*) malloc(DIM_IV);
	ret = RAND_bytes(&iv[0], DIM_IV);
	if (ret!=1)
		return false;
		
	if(pt_len < 0) return false;
	sumControl(sizeof(pt), sizeof(AAD));
	dim = sizeof(pt) + sizeof(AAD);
	sumControl(dim, sizeof(iv)); 
	dim += sizeof(iv);
	sumControl (dim, DIM_BLOCK);
	dim +=DIM_BLOCK; //padding
	cpt = (unsigned char*) malloc(dim);
	cpt_len = (int*) malloc (sizeof(int));
	*cpt_len = 0;
	
	
	
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	if(!ctx)
		return false;
	ret = EVP_EncryptInit(ctx, EVP_aes_128_gcm(), sessionkey, iv);
	if (ret != 1)
		return false;
	ret = EVP_EncryptUpdate(ctx, NULL, &howmany, (unsigned char*)AAD, strlen(AAD));
	subControlInt (pt_len, DIM_BLOCK);
	while (read < pt_len - DIM_BLOCK){
		ret= EVP_EncryptUpdate(ctx, cpt + read, &howmany, pt + read, DIM_BLOCK);
		if (ret != 1)
			return false;
		sumControl(read, DIM_BLOCK);
		sumControl (*cpt_len, howmany);
		read +=DIM_BLOCK;
		*cpt_len += howmany;
	}
	ret= EVP_EncryptUpdate(ctx, cpt + read, &howmany, pt + read, pt_len - read);
	if (ret != 1)
		return false;
	ret=EVP_EncryptFinal (ctx, (unsigned char*)cpt+howmany, &howmany);
	if (ret != 1)
		return false;
	sumControl(*cpt_len, howmany);
	*cpt_len += howmany;
	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, DIM_TAG, tag);
	if(ret !=1)
		return false;
	
	EVP_CIPHER_CTX_free(ctx);
	#pragma optimize("", off)
   	memset(iv, 0, DIM_IV);
	#pragma optimize("", on)
   	free(iv);
   	return true;
	
}


bool symmetricDecryption(unsigned char* pt, int* pt_len,  unsigned char* cpt, int cpt_len, unsigned char* sessionkey){
	
	int ret = 0;
	int read = 0;
	int howmany =0;
	int dim =0;
	unsigned char tag[DIM_TAG];
	if(pt_len < 0) return false;
	pt_len = (int*) malloc (sizeof(int));
	*pt_len = 0;

	
	unsigned char* iv = (unsigned char*) malloc(DIM_IV);
	if (!iv)
		return false;
	
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	if(!ctx)
		return false;
	
	//subControlInt(sizeof(cpt), DIM_BLOCK);
	subControlInt(sizeof(cpt), (int)DIM_IV);
	int cipher_len = sizeof(cpt) - (int)DIM_IV;
	subControlInt(cipher_len, (int)DIM_TAG);
	cipher_len -=(int)DIM_TAG;
	subControlInt(cipher_len, (int)DIM_AAD);
	cipher_len -= (int)DIM_AAD;
	
	unsigned char* cipher_buf = (unsigned char*) malloc (cipher_len);
	unsigned char* buf = (unsigned char*) malloc (cipher_len);
	unsigned char * aad = (unsigned char*) malloc ((int)DIM_AAD);
	if(!cipher_buf || !buf)
		return false;
	
	//Extract the IV
	extract_data_from_array(iv, cpt, 0, DIM_IV); 
	//Extract the ecrypted message
	extract_data_from_array(cipher_buf, cpt, DIM_IV, cipher_len); 
	//Extract the TAG
	sumControl(cipher_len, DIM_BLOCK);
	int start= cipher_len + DIM_BLOCK;
	extract_data_from_array(tag, cpt, start, DIM_TAG);
	//Extract AAD
	sumControl(start, DIM_TAG);
	start += DIM_TAG;
	extract_data_from_array(aad, cpt, start, DIM_AAD);
	
	ret = EVP_DecryptInit(ctx, EVP_aes_128_gcm(), sessionkey, iv);
	if(ret!= 1)
		return false;
	ret = EVP_DecryptUpdate (ctx, NULL, &howmany, aad, DIM_AAD);
	if(ret!= 1)
		return false;
	subControlInt(cipher_len,DIM_BLOCK);
	while(read < cipher_len - DIM_BLOCK){
		ret = EVP_DecryptUpdate(ctx, buf + read, &howmany, cipher_buf + read, DIM_BLOCK);
		if(ret!= 1)
			return false;
		sumControl (read, DIM_BLOCK);
		read +=DIM_BLOCK;
		sumControl(*pt_len, howmany);
		*pt_len = howmany;
	} 
	ret = EVP_DecryptUpdate(ctx, buf + read, &howmany, cipher_buf+read, cipher_len - read);
	if(ret !=1)
		return false;
	sumControl(*pt_len, howmany);
	*pt_len +=howmany;
	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, DIM_TAG, tag);
	if(ret !=1)
		return false;
	ret = EVP_DecryptFinal(ctx, buf+howmany, &howmany);
	if(ret !=1)
		return false;
	
	pt = (unsigned char*) malloc (*pt_len);
	memcpy(pt, buf, *pt_len);
	
	EVP_CIPHER_CTX_free(ctx);
	#pragma optimize("", off)
   	memset(iv, 0, DIM_IV);
   	memset(cipher_buf, 0, cipher_len);
   	memset(buf, 0, cipher_len);
   	memset(aad, 0, DIM_AAD);
	#pragma optimize("", on)
   	free(iv);
   	free(cipher_buf);
   	free(buf);
   	free(aad);
   	return true;
	
}



//function that derive the DH shared secret and stores its length into a variable. It returns NULL in case of error
unsigned char* DHSecretDerivation(EVP_PKEY* privK, EVP_PKEY* pubK, int* secretLen){
	unsigned char* secret;
	EVP_PKEY_CTX* derive_ctx;
	int ret;
	derive_ctx = EVP_PKEY_CTX_new(privK, NULL);
	if(derive_ctx == NULL)
		return NULL;
	ret = EVP_PKEY_derive_init(derive_ctx);
	if(ret <= 0)
		return NULL;
	ret = EVP_PKEY_derive_set_peer(derive_ctx, pubK);
	if(ret <= 0)
		return NULL;
	EVP_PKEY_derive(derive_ctx, NULL, secretLen);
	secret = (unsigned char*) malloc(*secretLen);
	if(secret == NULL)
		return NULL;
	EVP_PKEY_derive(derive_ctx, secret, secretLen);
	EVP_PKEY_CTX_free(derive_ctx);
	return secret;
}

