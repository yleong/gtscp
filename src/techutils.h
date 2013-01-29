/*Common utility functions for both techdec and techrypt*/
#ifndef TECHUTILS_H
#define TECHUTILS_H
#include "option.h"

/*cryptographic*/
int initGcrypt();
int deriveKey(char* password, char* salt, int numIterations, int keyLength,
	      char** key);
int aes_ctr  (char* key, int keyLength, char* inFile, long fileLength, char*
ctrInit, int blockLength,
              char** outFile);
int hmac     (char* key, int keyLength, char* outFile, long fileLength,
	      char** mac, int* macLength);

/*file IO*/
int readFile (char* fileName, 
	      long* fileLength, char** inFile);
int writeFile(char* fileName, char* outFile, long fileLength, char* mac, int
	macLength);

/*misc*/
int parseArgs(int argc, char** argv, 
	      char** fileName, char** ipAddress, int* port);
void checkErr(int err, char* msg);
void printKey(char* key, int keyLength);
#endif
