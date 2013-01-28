#include "techutils.h"
#include <stdio.h>
#include <unistd.h>

int sendFile(char* outFile, char* mac, char* ipAddr, int port);
char* USAGE_STR = "usage: techrypt < input file > [-d < IP-addr:port >][-l ]";
int main(int argc, char** argv){

    char *fileName, *inFile, *outFile, *mac, *ipAddr;  
    int port;
    int fileLength;
    int opt, err;  /*error codes*/
    char *password, *salt = "SodiumChloride";
    int keyLength = 32;
    int numIterations = 4096, ctrInit = 0;
    char *key;


    opt = parseArgs(argc, argv, &fileName, &ipAddr, &port);
    checkErr(opt, USAGE_STR);

    password = getpass("Password:");

    initGcrypt();
    err = deriveKey(password, salt, numIterations, keyLength, &key);
    checkErr(err, "Key derivation error");
    printKey(key, keyLength);

    err = readFile(fileName, &fileLength, &inFile);
    checkErr(err, "File read error");

    err = aes_ctr(key, inFile, fileLength, ctrInit, &outFile);
    checkErr(err, "Encryption error");

    err = hmac(key, outFile, fileLength, &mac);
    checkErr(err, "HMAC computation error");

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
