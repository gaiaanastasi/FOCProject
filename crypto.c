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
#define DIM_TAG 16
#define DIM_BLOCK 128
#define DIM_AAD 12
#define DIM_IV 12
#define DIR_SIZE 6
#define DIR "keys/"


//function that generate a nonce of DIM_NONCE bit
void generateNonce(unsigned char* nonce){
	if(RAND_poll() != 1)
		perror("error occured during RAND_poll()");
	if(RAND_bytes((unsigned char*)nonce, DIM_NONCE) != 1)
		perror("error occured during generation of the nonce");
	//printf("the nonce has been generated\n");
}



//function that return the signature for a given plaintext and in signatureLen its length
void signatureFunction(char* plaintext, int dimpt, char* signature, int* signatureLen, EVP_PKEY* myPrivK){
	EVP_MD_CTX* signCtx = NULL;		//signature context
	int ret = 0;
	signCtx = EVP_MD_CTX_new();
	if(!signCtx){
		perror("Error during context allocation\n");
		exit(-1);
	}
	ret = EVP_SignInit(signCtx, EVP_sha256());
	if(ret == 0){
		perror("Error during signInit()\n");
		exit(-1);
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
bool verifySignature (unsigned char* signature,  unsigned char* unsigned_msg, int signature_size, int unsigned_size, EVP_PKEY* pubkey){
	
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if(!ctx){
		perror("ctx was not allocated");
		exit(-1);
	}
	int ret = EVP_VerifyInit(ctx, EVP_sha256());
	if (ret !=1 ){
		perror("verifyInit");
		exit(-1);
	}
	ret=EVP_VerifyUpdate (ctx, unsigned_msg, unsigned_size);
	if (ret !=1 ){
		perror("verifyUpdate");
		exit(-1);
	}
	ret = EVP_VerifyFinal(ctx, signature, signature_size, pubkey);
	if (ret !=1 ){
		perror("authentication error");
		return false;
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

//function that allocates and generates Diffie-Hellman private key
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
	dhPrivateKey = NULL;
	ret = EVP_PKEY_keygen(DHctx, &dhPrivateKey);
	if(ret != 1){
		perror("Error during generation of Diffie-Hellman key\n");
		exit(-1);
	}	
	EVP_PKEY_CTX_free(DHctx);
	EVP_PKEY_free(DHparams);
	return dhPrivateKey;
}

EVP_PKEY* getUserPbkey (unsigned char* username){
	EVP_PKEY* pubkey;
	sumControl(DIR_SIZE, DIM_SUFFIX_FILE_PUBKEY);
	sumControl(DIM_USERNAME, (DIM_SUFFIX_FILE_PUBKEY+DIR_SIZE));
	int name_size = DIM_USERNAME + DIM_SUFFIX_FILE_PUBKEY + DIR_SIZE;
	char* fileName = (char*) malloc(name_size);
	if(!fileName){
		perror("malloc");
		exit(-1);
	}
	strncpy(fileName, (char*)DIR, DIR_SIZE );
	subControlInt(DIR_SIZE, 1);
	fileName[DIR_SIZE - 1] ='\0';
	strncat(fileName, (char*)username, DIM_USERNAME );
	strncat(fileName, "_pubkey.pem", DIM_SUFFIX_FILE_PUBKEY);
	FILE* file = fopen(fileName, "r");
	if(!file){
		perror("fopen");
		exit(-1);
	}
	free(fileName);
	//Retrive client's public key
	pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
	if (!pubkey){
		perror("Pubkey not found");
		exit(-1);
	}
	fclose(file);
	return pubkey;
}

//Function that allocates and returns the serialization of a public key. It returns NULL in case of error
unsigned char* serializePublicKey(EVP_PKEY* privK, int* bufferLen){
	BIO* myBio;
	int ret;
	unsigned char* buffer;
	myBio = BIO_new(BIO_s_mem());
	if(myBio == NULL)
		return NULL;
	ret = PEM_write_bio_PUBKEY(myBio, privK);
	if(ret != 1)
		return NULL;
	buffer = NULL;
	*bufferLen = BIO_get_mem_data(myBio, &buffer);
	buffer = (unsigned char*) malloc(*bufferLen);
	if(!buffer){
		perror("malloc");
		exit(-1);
	}
	ret = BIO_read(myBio, (void*) buffer, *bufferLen);
	if(ret <= 0)
		return NULL;
	BIO_free(myBio);
	return buffer;
}

//Function that allocates and returns the deserialized public key. It returns NULL in case of error
EVP_PKEY* deserializePublicKey(unsigned char* buffer, int bufferLen){
	EVP_PKEY* pubKey;
	int ret;
	BIO* myBio;
	myBio = BIO_new(BIO_s_mem());
	if(myBio == NULL)
		return NULL;
	ret = BIO_write(myBio, buffer, bufferLen);
	if(ret <= 0)
		return NULL;
	pubKey = PEM_read_bio_PUBKEY(myBio, NULL, NULL, NULL);
	if(pubKey == NULL)
		return NULL;
	BIO_free(myBio);
	return pubKey;
}

//Function that allocates and derive a symmetric key for aes_128_gcm by means of the DH shared secret, derived by using the two keys. It returns NULL in case of error
unsigned char* symmetricKeyDerivation_for_aes_128_gcm(EVP_PKEY* privK, EVP_PKEY* pubK){
	unsigned char* secret;
	int secretLen;
	unsigned char* digest;
	int digestLen;
	unsigned char* key;
	int keyLen;
	EVP_MD_CTX* Hctx;
	EVP_PKEY_CTX* derive_ctx;
	int ret;
	const EVP_CIPHER* cipher = EVP_aes_128_gcm();;
	//secret derivation
	derive_ctx = EVP_PKEY_CTX_new(privK, NULL);
	if(derive_ctx == NULL)
		return NULL;
	ret = EVP_PKEY_derive_init(derive_ctx);
	if(ret <= 0)
		return NULL;
	ret = EVP_PKEY_derive_set_peer(derive_ctx, pubK);
	if(ret <= 0)
		return NULL;
	EVP_PKEY_derive(derive_ctx, NULL, (size_t*)&secretLen);
	secret = (unsigned char*) malloc(secretLen);
	if(secret == NULL)
		return NULL;
	EVP_PKEY_derive(derive_ctx, secret, (size_t*)&secretLen);
	EVP_PKEY_CTX_free(derive_ctx);
	//key derivation by hashing the shared secret
	Hctx = EVP_MD_CTX_new();
	digest = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));
	if(!digest){
		perror("malloc");
		exit(-1);
	}
	ret = EVP_DigestInit(Hctx, EVP_sha256());
	if(ret != 1)
		return NULL;
	ret = EVP_DigestUpdate(Hctx, secret, secretLen);
	if(ret != 1)
		return NULL;
	ret = EVP_DigestFinal(Hctx, digest, (unsigned int*)&digestLen);
	if(ret != 1)
		return NULL;
	EVP_MD_CTX_free(Hctx);
	keyLen = EVP_CIPHER_key_length(cipher);
	key = (unsigned char*) malloc(keyLen);
	if(!key){
		perror("malloc");
		exit(-1);
	}
	if(!memcpy(key, digest, keyLen))
		return NULL;
#pragma optimize("", off);
	memset(digest, 0, digestLen);
	memset(secret, 0, secretLen);
#pragma optimize("", on);
	free(secret);
	free(digest);
	return key;
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

//Function that takes a plaintext and allocates and returns a message formatted like { <encrypted_key> | <IV> | <ciphertext> } in an asimmetric encryption and store its length in dimM. Return NULL in case of error
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
	const EVP_CIPHER* cipher = EVP_aes_128_cbc();
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
	sumControl(nctot, nc);
	nctot += nc;
	ret = EVP_SealFinal(ctx, ciphertext + nctot, &nc);
	if(ret == 0)
		return NULL;
	sumControl(nctot, nc);
	nctot += nc;
	cpt_len = nctot;

	EVP_CIPHER_CTX_free(ctx);
#pragma optimize("", off)
   	memset(pt, 0, pt_len);
#pragma optimize("", on)
   	free(pt);

	//message constitution
	sumControl(encrypted_key_len, iv_len);
	dimB = encrypted_key_len + iv_len;
	buffer = (unsigned char*) malloc(dimB);
	if(!buffer){
		perror("malloc");
		exit(-1);
	}
	concat2Elements(buffer, encrypted_key, iv, encrypted_key_len, iv_len);
	sumControl(dimB, cpt_len);
	*dimM = dimB + cpt_len;
	message = (unsigned char*) malloc(*dimM);
	if(!message){
		perror("malloc");
		exit(-1);
	}
	concat2Elements(message, buffer, ciphertext, dimB, cpt_len);
	free(iv);
	free(encrypted_key);
	free(ciphertext);
   	return message;
}

//takes the received message (formatted { <encrypted_key> | <IV> | <ciphertext> }) and allocates and returns the respective plaintext and stores its length in pt_len. Return NULL in case of error
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
	const EVP_CIPHER* cipher = EVP_aes_128_cbc(); 
	encrypted_key_len = EVP_PKEY_size(prvKey);
	iv_len = EVP_CIPHER_iv_length(cipher);
	sumControl(encrypted_key_len, iv_len);
	//check for correct format of the encrypted file
	if(messageLen < encrypted_key_len + iv_len)
		return NULL;
	encrypted_key = (unsigned char*) malloc(encrypted_key_len);
	iv = (unsigned char*) malloc(iv_len);
	cpt_len = messageLen - encrypted_key_len - iv_len;	//possible overflow already controlled
	cpt = (unsigned char*) malloc(cpt_len);
	pt = (unsigned char*) malloc(cpt_len);
	if(!iv || !encrypted_key || !cpt || !pt)
		return NULL;
	extract_data_from_array(encrypted_key, message, 0, encrypted_key_len);
	sumControl(encrypted_key_len, iv_len);
	extract_data_from_array(iv, message, encrypted_key_len, encrypted_key_len + iv_len);
	extract_data_from_array(cpt, message, encrypted_key_len + iv_len, messageLen);
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
	sumControl(ndtot, nd);
	ndtot += nd;
	ret = EVP_OpenFinal(ctx, pt + ndtot, &nd);
	if(ret == 0)
		return NULL;
	sumControl(ndtot, nd);
	ndtot += nd;
	*pt_len = ndtot;
	EVP_CIPHER_CTX_free(ctx);
	free(encrypted_key);
	free(iv);
	free(cpt);
	return pt;	

}

//function that takes a plaintext and returns a buffer that has the format { <IV> | <AAD> | <tag> | <ciphertext> }. It returns NULL in case of error
unsigned char* symmetricEncryption(unsigned char *plaintext, int plaintext_len, unsigned char *key, int *totalLen, int* counter)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
	int ret = 0;
    int ciphertext_len = 0;
	unsigned char* outBuffer;
	unsigned char* tag = (unsigned char*) malloc(DIM_TAG);
	sumControl(plaintext_len, DIM_TAG);
	unsigned char* ciphertext = (unsigned char*) malloc(plaintext_len + DIM_TAG);
	unsigned char* iv = (unsigned char*) malloc(DIM_IV);
	unsigned char* AAD = (unsigned char*) malloc(DIM_AAD);
	if(!tag | !ciphertext | !iv | !AAD){
		perror("malloc");
		exit(-1);
	}
	sprintf(AAD, "%d", *counter);
	IncControl(*counter);
	(*counter)++;
	ret = RAND_bytes(&iv[0], DIM_IV);
	if (ret!=1)
		return NULL;
	ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        return NULL;
	ret = EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv);
    if(1 != ret)
        return NULL;
	ret = EVP_EncryptUpdate(ctx, NULL, &len, AAD, DIM_AAD);
    if(1 != ret)
        return NULL;
	ret = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    if(1 != ret)
        return NULL;
    ciphertext_len = len;
	ret = EVP_EncryptFinal(ctx, ciphertext + len, &len);
    if(1 != ret)
        return NULL;
	sumControl(ciphertext_len, len);
    ciphertext_len += len;
	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
    if(1 != ret)
        return NULL;
    EVP_CIPHER_CTX_free(ctx);
	sumControl(ciphertext_len, DIM_TAG);
	sumControl(ciphertext_len+DIM_TAG, DIM_IV);
	sumControl(ciphertext_len+DIM_TAG+DIM_IV, DIM_AAD);
    *totalLen = ciphertext_len + DIM_TAG + DIM_IV + DIM_AAD;
	outBuffer = (unsigned char*) malloc(*totalLen);
	if(!outBuffer){
		perror("malloc");
		exit(-1);
	}
	concatElements(outBuffer, iv, 0, DIM_IV);
	concatElements(outBuffer, AAD, DIM_IV, DIM_AAD);
	sumControl(DIM_AAD, DIM_IV);
	concatElements(outBuffer, tag, DIM_AAD + DIM_IV, DIM_TAG);
	sumControl(DIM_AAD+ DIM_IV, DIM_TAG);
	concatElements(outBuffer, ciphertext, DIM_AAD + DIM_IV + DIM_TAG, ciphertext_len);
	free(ciphertext);
	free(iv);
	free(tag);
	free(AAD);
	return outBuffer;
}

//function that takes a buffer formatted as { <IV> | <AAD> | <tag> | <ciphertext> } and return the plaintext. It returns NULL in case of error
unsigned char* symmetricDecription(unsigned char *recv_buffer, int bufferLen, int *plaintext_len, unsigned char* key, int* expectedAAD)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ret;
	unsigned char* iv;
	unsigned char* aad;
	unsigned char* tag;
	unsigned char* ciphertext;
	int ciphertext_len = bufferLen - DIM_IV - DIM_AAD - DIM_TAG;
	unsigned char* plaintext;
	unsigned char* buffer = (unsigned char*) malloc(ciphertext_len);
	//extract informations
	ciphertext = (unsigned char*) malloc(ciphertext_len);
	iv = (unsigned char*) malloc(DIM_IV);
	aad = (unsigned char*) malloc(DIM_AAD);
	tag = (unsigned char*) malloc(DIM_TAG);
	if(!aad | !iv | !tag | !ciphertext){
		perror("Error during malloc()");
		exit(-1);
	}
	extract_data_from_array(iv, recv_buffer, 0, DIM_IV);
	sumControl(DIM_AAD, DIM_IV);
	sumControl(DIM_IV+DIM_AAD, DIM_TAG);
	extract_data_from_array(aad, recv_buffer, DIM_IV, DIM_IV + DIM_AAD);
	extract_data_from_array(tag, recv_buffer, DIM_IV + DIM_AAD, DIM_IV + DIM_AAD + DIM_TAG);
	extract_data_from_array(ciphertext, recv_buffer, DIM_IV + DIM_AAD + DIM_TAG, bufferLen);
	if(atoi(aad) != expectedAAD){
		perror("The two counters are different");
		exit(-1);
	}
	IncControl(*expectedAAD);
	(*expectedAAD)++;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return NULL;
    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return NULL;
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, DIM_AAD))
        return NULL;
    if(!EVP_DecryptUpdate(ctx, buffer, &len, ciphertext, ciphertext_len))
        return NULL;
    *plaintext_len = len;
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        return NULL;
    ret = EVP_DecryptFinal(ctx, buffer + len, &len);

	EVP_CIPHER_CTX_free(ctx);

    if(ret < 0)
		return NULL;
	sumControl(*plaintext_len, len);
	*plaintext_len += len;
	plaintext = (unsigned char*) malloc((*plaintext_len));
	if(!plaintext){
		perror("Error during malloc()");
		exit(-1);
	}
	memcpy(plaintext, buffer, *plaintext_len);
	free(tag);
	free(iv);
	free(aad);
	free(buffer);
	free(ciphertext);
	return plaintext;
}
