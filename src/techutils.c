#include <stdio.h>
#include <stdlib.h>
#include "option.h"

/*cryptographic*/
int deriveKey(char* password, char* salt, int numIterations, 
	      char** key){
    return NONE;
}
int aes_ctr  (char* key, char* inFile, int fileLength, int ctrInit,
              char** outFile){
    return NONE;
}
int hmac     (char* key, char* outFile, int fileLength,
	      char** mac ){
    return NONE;
}

/*file IO*/
int readFile (char* fileName,
	      int* fileLength, char** inFile){
    return NONE;
}
int writeFile(char* fileName, char* outFile, char* mac){
    /*check if exists -> error code 33*/
    return NONE;
}

/*misc*/
int parseArgs(int argc, char** argv, 
	      char** fileName, char** ipAddress, int* port){
    return NONE;
}

int checkErr(int err, char* msg){
    if(ERROR == err){
	printf("%s\n", msg);
	exit(err);
    }
}
