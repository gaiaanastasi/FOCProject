#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdbool.h>

#define DIM_NONCE 16
#define DIM_USERNAME 32
#define DIM_SUFFIX_FILE_PUBKEY 12
#define DIM_SUFFIX_FILE_PRIVKEY 13
#define DIM_PASSWORD 32
#define AAD "0000"

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

//function that generates Diffie-Hellman low level parameters in a EVP_PKEY variable
void generateDHParams(EVP_PKEY* params){
	int ret;
	DH* temp = get_dh2048();
	ret = EVP_PKEY_set1_DH(params, temp);
	if(ret != 1){
		perror("Error during the copy of the low level DH parameters\n");
		exit(-1);
	}
	DH_free(temp);
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

//function that stores the ciphertext, the encrypted key and the IV of a digital envelope. It returns false in case of error
bool createDigitalEnvelope(EVP_CIPHER* cipher, unsigned char* pt, int pt_len, unsigned char* encrypted_key, int encrypted_key_len, unsigned char* iv, int iv_len, unsigned char* cpt, int* cpt_len, EVP_PKEY* pubkey){
	int ret;
	int nc = 0;		//bytes encrypted at each chunk
	int nctot = 0;	//total encrypted bytes
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL)
		return false;
	ret = EVP_SealInit(ctx, cipher, (unsigned char**)&encrypted_key, &encrypted_key_len, (unsigned char*)iv, &pubkey, 1);
	if(ret < 0)
		return false;
	ret = EVP_SealUpdate(ctx, (unsigned char*) cpt, &nc, (unsigned char*)pt, pt_len);
	if(ret == 0)
		return false;
	nctot += nc;
	ret = EVP_SealFinal(ctx, (unsigned char*)cpt + nctot, &nc);
	if(ret == 0)
		return false;
	nctot += nc;
	*cpt_len = nctot;

	EVP_CIPHER_CTX_free(ctx);
#pragma optimize("", off)
   	memset(pt, 0, pt_len);
#pragma optimize("", on)
   	free(pt);
   	return true;
}

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
	EVP_CIPHER_CTX(ctx);
}

//function for symmetric encryption
bool symmetricEncryption(EVP_CIPHER* cipher, char* pt, int pt_len,  char* iv, int iv_len, char* cpt, int* cpt_len, EVP_PKEY* sessionkey){
	
	int ret = 0;
	
	int read = 0;
	int howmany =0;
	char* tag = (char*) malloc (16);

	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	ret = EVP_EncryptInit(ctx, EVP_aes_128_gcm(), (unsigned char*)sessionkey, (unsigned char*)iv);
	if (ret != 1)
		return false;
	ret = EVP_EncryptUpdate(ctx, NULL, &howmany, (unsigned char*)AAD, strlen(AAD));
	while (read < pt_len - 128){
		ret= EVP_EncryptUpdate(ctx, (unsigned char*)cpt + read, &howmany, (unsigned char*)pt + read, pt_len - read);
		if (ret != 1)
			return false;
		read +=128;
	}
	ret= EVP_EncryptUpdate(ctx, (unsigned char*)cpt + read, &howmany, (unsigned char*) pt + read, pt_len - read);
	if (ret != 1)
		return false;
	EVP_EncryptFinal (ctx, (unsigned char*)tag, &howmany);
	if (ret != 1)
		return false;
	cpt_len = &howmany;
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
	#pragma optimize("", off)
   	memset(tag, 0, 16);
	#pragma optimize("", on)
	free(tag);
	free(ctx);
	return true;
	
}


//function that derive the DH shared secret and stores it into a buffer. It returns NULL in case of error
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