/*Common utility functions for both techdec and techrypt*/
#ifndef TECHUTILS_H
#define TECHUTILS_H
#include "option.h"

/*cryptographic*/
int deriveKey(char* password, char* salt, int numIterations, 
	      char** key);
int aes_ctr  (char* key, char* inFile, int fileLength, int ctrInit,
              char** outFile);
int hmac     (char* key, char* outFile, int fileLength,
	      char** mac );

/*file IO*/
int readFile (char* fileName, 
	      int* fileLength, char** inFile);
int writeFile(char* fileName, char* outFile, char* mac);

/*misc*/
int parseArgs(int argc, char** argv, 
	      char** fileName, char** ipAddress, int* port);
void checkErr(int err, char* msg);
#endif
