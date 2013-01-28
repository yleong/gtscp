#include "techutils.h"
#include <stdio.h>
#include <unistd.h>

int sendFile(char* outFile, char* mac, char* ipAddr, int port);
char* USAGE_STR = "usage: techrypt < input file > [-d < IP-addr:port >][-l ]";
int main(int argc, char** argv){

    char *fileName, *inFile, *outFile, *mac, *ipAddr;  
    int port;
    int opt, err;  /*error codes*/
    char *password, *salt = "SodiumChloride";
    int numIterations = 4096, ctrInit = 0;
    char *key;


    opt = parseArgs(argc, argv, &fileName, &ipAddr, &port);
    checkErr(opt, USAGE_STR);

    password = getpass("Password:");

    err = deriveKey(password, salt, numIterations, &key);
    checkErr(err, "Key derivation error");

    err = readFile(fileName, &inFile);
    checkErr(err, "File read error");

    err = aes_ctr(key, inFile, ctrInit, &outFile);
    checkErr(err, "Encryption error");

    err = hmac(key, outFile, &mac);
    checkErr(err, "HMAC error");

    if(D_SEND == opt){
	err = sendFile(outFile, mac, ipAddr, port);
	checkErr(err, "File send error");
    } else if(L_LOCAL == opt){
	err = writeFile(fileName, outFile, mac);
	checkErr(err, "File write error");
    }
    
    return 0;
}

int sendFile(char* outFile, char* mac, char* ipAddr, int port){
    return NONE;
}