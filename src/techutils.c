#include <stdio.h>
#include <stdlib.h>
#include "option.h"
#include <string.h>
#include <gcrypt.h>

/*cryptographic*/
int initGcrypt(){
    const int MAX_SECURE_MEM = 16384;
    if(! gcry_check_version("1.5.0")){
	return GCRYPT_VERSION_ERROR;
    }
    /*suppress warnings*/
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    /*allocate 16k of secure memory*/
    gcry_control (GCRYCTL_INIT_SECMEM, MAX_SECURE_MEM, 0);
    /*re-enable warnings*/
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
    /* Tell Libgcrypt that initialization has completed. */
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

int deriveKey(char* password, char* salt, int numIterations, int keyLength,
	      char** key){
    gpg_error_t err;
    size_t KEY_LENGTH = keyLength;
    *key = (char*)(malloc(KEY_LENGTH * sizeof(char)));

    /*
    DPRINT("deriving key using password %s %d len salt %s %d len %d iterations \
	    with key length %d \n", password, strlen(password),
	    salt, strlen(salt),  numIterations, KEY_LENGTH);
    */
    err = gcry_kdf_derive(password, strlen(password), 
	    GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, strlen(salt),
	    numIterations, KEY_LENGTH, *key);

    DPRINT("derived key of %s \n", password);
    if(err){ return KEY_DERIVE_ERROR;}
    return NONE;
}
int aes_ctr  (char* key, int keyLength, char* inFile, long fileLength, char*
	      ctrInit, int blockLength,
              char** outFile){
    gcry_error_t err;
    gcry_cipher_hd_t aeshd;

    err = gcry_cipher_open(&aeshd, GCRY_CIPHER_AES256,
	                           GCRY_CIPHER_MODE_CTR,
	                           GCRY_CIPHER_SECURE);
    if(err){return CIPHER_OPEN_ERROR;}

    err = gcry_cipher_setkey(aeshd, key, keyLength);
    if(err){return CIPHER_SETKEY_ERROR;}
    
    err = gcry_cipher_setctr(aeshd, ctrInit, blockLength);
    if(err){return CIPHER_SETCTR_ERROR;}

    *outFile = (char*)(malloc(fileLength * sizeof(char)));
    DPRINT("going to enc/dec now\n");
    err = gcry_cipher_encrypt(aeshd, *outFile, fileLength, inFile, fileLength);
    if(err){return CIPHER_ENCRYPT_ERROR;}

    DPRINT("done with enc/dec\n");
    gcry_cipher_close(aeshd);
    return NONE;
}
int hmac     (char* key, int keyLength, char* outFile, long fileLength,
	      char** mac, int* macLength ){
    DPRINT("\nin hmac.\n");
    gcry_error_t err;
    gcry_md_hd_t shahd;

    DPRINT("opening hash\n");
    err = gcry_md_open(&shahd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    if(err){ return MD_OPEN_ERROR;}

    DPRINT("setting key\n");
    err = gcry_md_setkey(shahd, key, keyLength);
    if(err){ return MD_SETKEY_ERROR;}

    DPRINT("actually hashing\n");
    DPRINT("%ld\n",fileLength);
    gcry_md_write(shahd, outFile, fileLength);

    DPRINT("done hashing\n");
    *macLength = 32;

    char* temp;
    temp = gcry_md_read(shahd, GCRY_MD_SHA256);

    DPRINT("preparing to read hash\n");
    /*copy it over since closing shahd would free the mac.*/
    *mac = (char*)(malloc(*macLength * sizeof(char)));
    memcpy(*mac, temp, *macLength);

    gcry_md_close(shahd);
    return NONE;
}

/*file IO*/
/*Reads the entire file into char* inFile*/
int readFile (char* fileName,
	      long* fileLength, char** inFile){
    FILE *in = fopen(fileName, "rb");
    if(NULL == in){
	return FOPEN_ERROR; 
    }
    fseek(in, 0, SEEK_END);
    *fileLength = ftell(in);
    fseek(in, 0, SEEK_SET);

    *inFile = (char*)(malloc( (*fileLength) * sizeof(char)));
    fread(*inFile, sizeof(char), *fileLength, in);

    fclose(in);
    
    return NONE;
}
int writeFile(char* fileName, char* outFile, long fileLength, char* mac, int
	macLength){
    int isTechDec = (NULL == mac);
    char * extension = ".gt";
    char * outFileName;
    int outFileNameLen;

    /*techdec removes the extension, techrypt adds the extension*/
    /*check if exists -> error code 33*/
    if(isTechDec){
	/*strip the extension*/
	outFileNameLen = strlen(fileName) - strlen(extension) + 1; /*for null*/
	outFileName = (char *)(malloc(outFileNameLen*sizeof(char)));
	strncpy(outFileName, fileName, outFileNameLen-1);
	outFileName[outFileNameLen-1] = '\0';
    } else {
	/*append the extension*/
	outFileNameLen = strlen(fileName) + strlen(extension) + 1; /*for null*/
	outFileName = (char *)(malloc(outFileNameLen*sizeof(char)));
	strncpy(outFileName, fileName, strlen(fileName)+1);
	strcat(outFileName, extension);
    }
    DPRINT("output file name: %s \n", outFileName);


    /*test if file exists*/
    FILE *test = fopen(outFileName, "r");
    if(NULL != test){  return OUT_FILE_EXISTS_ERROR;}

    FILE *out = fopen(outFileName, "wb");
    if(NULL == out){ DPRINT("cannot open out file!\n");return FOPEN_ERROR;}

    DPRINT("writing outFile\n");
    fwrite(outFile, sizeof(char), fileLength, out);
    if(!isTechDec){
	DPRINT("writing mac\n");
	/*write the mac*/
	fwrite(mac, sizeof(char), macLength, out);
    } 

    fclose(out);

    return NONE;
}

/*misc*/
/*ipAddress parameter can be NULL since techdec does not use it.*/
int parseArgs(int argc, char** argv, 
	      char** fileName, char** ipAddress, int* port){
    /*for reference
    "usage: techrypt < input file > [-d < IP-addr:port >][-l ]"
    "usage: techdec < filename >  [-d < port >][-l] "
    */

    int isTechDec = (ipAddress == NULL);
    int option;

    if( (argc <= 1) ||  (argc > 4)){
	return NUM_ARGS_ERROR;
    }

    /* argc = 2, 3, 4*/
    *fileName = argv[1];
    DPRINT("fileName: %s ", *fileName);

    if(argc >= 3){

	/*In case of daemon*/
	if(strcmp("-d", argv[2]) == 0){
	    option = ((isTechDec) ? D_DAEMON : D_SEND);
	    if(argc == 4){ /*get ipaddr and port num*/
		if(!isTechDec){
		    char* delimPos = strchr(argv[3], ':');
		    if(NULL == delimPos){ return STRCHR_ERROR;}
		    *delimPos = '\0';
		    *ipAddress = argv[3];
		    *port = atoi((delimPos+ 1));
		    DPRINT("ip: %s:%d ", *ipAddress, *port);
		} else{
		    *port = atoi(argv[3]);
		    DPRINT("port: %d ", *port);
		}
		if(0 == *port){ return PORT_ERROR;}
	    } else{
		return MISSING_IPPORT_ERROR; 
	    }

	/*In case of local*/
	} else if(strcmp("-l", argv[2]) == 0){
	    option = L_LOCAL;
	    if(argc != 3){
		return ERROR;
	    }
	} else{
	    return UNKNOWN_OPT_ERROR;
	}
    } else if(argc == 2){
	option = L_LOCAL; /* this is implied*/
    }

    return option;
}

void checkErr(int err, char* msg){
    if(NONE != err && L_LOCAL != err && D_DAEMON != err && D_SEND != err){
	printf("%s\n", msg);
	exit(err);
    }
}
/*prints the key as hexadecimal*/
void printKey(char* key, int keyLength){

    int i;
    printf("Key:");
    for(i = 0; i < keyLength; i++){
	printf(" %02X", (unsigned char)(*(key+i)));
    }
}
