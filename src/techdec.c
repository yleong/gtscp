#include "techutils.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int receiveFile(int port, 
	        char** inFile, long* fileLength);
int verifyMac(char* key, char* inFile, long fileLength);
char* USAGE_STR = "usage: techdec < filename >  [-d < port >][-l] ";
int main(int argc, char** argv){
    char *fileName, *inFile, *outFile;  
    int port;
    long fileLength;
    int opt, err;  /*error codes*/
    char *password, *salt = "SodiumChloride";
    int keyLength = 32, macLength, blockLength = 16;
    int numIterations = 4096;
    char *ctrInit;  
    char *key;

    opt = parseArgs(argc, argv, &fileName, NULL, &port);
    checkErr(opt, USAGE_STR);

    password = getpass("Password:");

    initGcrypt();
    err = deriveKey(password, salt, numIterations, keyLength, &key);
    checkErr(err, "Key derivation error");
    printKey(key, keyLength);

    if(D_DAEMON == opt){
	err = receiveFile(port, &inFile, &fileLength);
	checkErr(err, "File receive error");
    
    } else if(L_LOCAL == opt){
	err = readFile(fileName, &fileLength, &inFile );
	checkErr(err, "File read error");
    }

    err = verifyMac(key, inFile, fileLength);
    checkErr(err, "HMAC verification error");

    ctrInit = (char*)(malloc(blockLength * sizeof(char)));
    /*using a zero counter each time*/
    memset((void *)ctrInit, 0, (size_t)(blockLength * sizeof(char))); 


    /*testing only!!!!!!!!!!!!!!!!!!!!*/ 
    int foo = 14;
    /*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
      





    err = aes_ctr(key, keyLength, inFile, fileLength - foo /* HMAC_LENGTH */, ctrInit,
	    blockLength, &outFile);
    checkErr(err, "Decryption error");









	/*DEBUGGING ONLY PLS REMOVE!!!!!!*/
	//outFile = inFile;
	/*!!!!!!!!!!!!*/









    err = writeFile(fileName, outFile, fileLength, NULL, 1);
    checkErr(err, "File write error");

    return 0;
}
int receiveFile(int port, 
	        char** inFile, long* fileLength){
    return NONE;
}
int verifyMac(char* key, char* inFile, long fileLength){
    int err, macLength;
    char* mac;

    err = hmac(key, inFile, fileLength - HMAC_LENGTH,  &mac, &macLength);
    checkErr(err, "HMAC computation error");
    return NONE;
}
