#include "techutils.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int sendFile(char* outFile, char* mac, char* ipAddr, int port);
char* USAGE_STR = "usage: techrypt < input file > [-d < IP-addr:port >][-l ]";
int main(int argc, char** argv){

    char *fileName, *inFile, *outFile, *mac, *ipAddr;  
    int port;
    long fileLength;
    int opt, err;  /*error codes*/
    char *password, *salt = "SodiumChloride";
    int keyLength = 32, macLength = 32, blockLength = 16;
    int numIterations = 4096;
    char * ctrInit;    char *key;


    opt = parseArgs(argc, argv, &fileName, &ipAddr, &port);
    DPRINT("got option: %d", opt);
    checkErr(opt, USAGE_STR);

    password = getpass("Password:");

    initGcrypt();
    err = deriveKey(password, salt, numIterations, keyLength, &key);
    checkErr(err, "Key derivation error");
    printKey(key, keyLength);

    err = readFile(fileName, &fileLength, &inFile);
    checkErr(err, "File read error");

    ctrInit =  (char*)(malloc(blockLength * sizeof(char)));
    /*using a zero counter each time*/
    memset((void*)ctrInit, 0, (size_t)(blockLength * sizeof(char)) ); 
    err = aes_ctr(key, keyLength, inFile, fileLength, ctrInit, blockLength,
	    &outFile); checkErr(err, "Encryption error");

    err = hmac(key, keyLength, outFile, fileLength, &mac, &macLength);
    checkErr(err, "HMAC computation error");

    if(D_SEND == opt){
	err = sendFile(outFile, mac, ipAddr, port);
	checkErr(err, "File send error");
    } else if(L_LOCAL == opt){
	DPRINT("writing file locally\n");
	err = writeFile(fileName, outFile, fileLength, mac, macLength);
	checkErr(err, "File write error");
    }
    
    return 0;
}

int sendFile(char* outFile, char* mac, char* ipAddr, int port){
    return NONE;
}
