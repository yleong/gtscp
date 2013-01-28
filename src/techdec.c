#include "techutils.h"
#include <stdio.h>
#include <unistd.h>

int receiveFile(int port, 
	        char** inFile, int* fileLength);
int verifyMac(char* key, char* inFile, int fileLength);
char* USAGE_STR = "usage: techdec < filename >  [-d < port >][-l] ";
int main(int argc, char** argv){
    char *fileName, *inFile, *outFile;  
    int port;
    int fileLength;
    int opt, err;  /*error codes*/
    char *password, *salt = "SodiumChloride";
    int keyLength = 32;
    int numIterations = 4096, ctrInit = 0;
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

    err = aes_ctr(key, inFile, fileLength - HMAC_LENGTH, ctrInit, &outFile);
    checkErr(err, "Decryption error");

    return 0;
}
int receiveFile(int port, 
	        char** inFile, int* fileLength){
    return NONE;
}
int verifyMac(char* key, char* inFile, int fileLength){
    int err;
    char* mac;

    err = hmac(key, inFile, fileLength - HMAC_LENGTH,  &mac);
    checkErr(err, "HMAC computation error");
    return NONE;
}
