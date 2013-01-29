#include "techutils.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/*Network includes*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

int receiveFile(int port, 
	        char** inFile, long* fileLength);
int verifyMac(char* key, int keyLength, char* inFile, long fileLength, int
	macLength);
int recvAll(int socket, char* buff, long len);
char* USAGE_STR = "usage: techdec < filename >  [-d < port >][-l] ";
int main(int argc, char** argv){
    char *fileName, *inFile, *outFile;  
    int port;
    long fileLength=0;
    int opt, err;  /*error codes*/
    char *password, *salt = "SodiumChloride";
    int keyLength = 32, macLength = 32, blockLength = 16;
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

    err = verifyMac(key, keyLength, inFile, fileLength, macLength);
    checkErr(err, "HMAC verification error");

    ctrInit = (char*)(malloc(blockLength * sizeof(char)));
    /*using a zero counter each time*/
    memset((void *)ctrInit, 0, (size_t)(blockLength * sizeof(char))); 

    err = aes_ctr(key, keyLength, inFile, fileLength - macLength, ctrInit,
	    blockLength, &outFile);
    checkErr(err, "Decryption error");

    err = writeFile(fileName, outFile, fileLength - macLength, NULL, 1, opt);
    checkErr(err, "File write error");

    return 0;
}

int receiveFile(int port, 
	        char** inFile, long* fileLength){
    int receiveSocket, acceptedSocket;
    int err, portStrlen;
    char *portStr;
    struct addrinfo *res, *curr;
    struct addrinfo hints;
    struct sockaddr incomingAddr;
    socklen_t incomingAddrSize = sizeof(incomingAddr);
     
    /*set up the hints to let addrinfo knows what flags to filter etc*/
    /*unused fields should be 0*/
    memset(&hints, 0, sizeof(hints));
    /*ipv4*/
    hints.ai_family = AF_INET; 
    /*TCP is needed to transfer ciphertext reliably*/
    hints.ai_socktype = SOCK_STREAM;
    /*automatically use localhost*/
    hints.ai_flags = AI_PASSIVE;
    
    /*Convert port number to string*/
    portStrlen = ceil(log10((float)(port))) + 1; /* 1 for \0*/
    portStr = (char *)(malloc(portStrlen * sizeof(char)));
    sprintf(portStr, "%d", port);

    err = getaddrinfo(NULL,portStr, &hints, &res);
    if(err){return GETADDR_ERROR;}

    /*get a bound socket out of list: res*/
    err = -1;
    curr = res;
    while(NULL != curr){
	receiveSocket = socket((*curr).ai_family, (*curr).ai_socktype,
			    (*curr).ai_protocol);
	if(-1 != receiveSocket){
	    err = bind(receiveSocket, (*curr).ai_addr, (*curr).ai_addrlen);
	    //err = connect(sendSocket, (*curr).ai_addr, (*curr).ai_addrlen);
	}
	if(-1 != err){
	    /*successfully connected*/
	    break;
	}
	/*try the next one*/
	close(receiveSocket);
	curr = (*curr).ai_next;
    }

    /*exhausted res but still no available sockets*/
    if(NULL == curr){
	return NO_SOCK_ERROR;
    }
    freeaddrinfo(res);

    long amtReceived = 0;
    DPRINT("going to listen\n");
    err = listen(receiveSocket, 1);
    if(err) {return ERROR;}
    DPRINT("now listening\n");

    acceptedSocket = accept(receiveSocket, &incomingAddr, &incomingAddrSize);
    if(-1 == acceptedSocket){DPRINT("invalid socket\n"); return ERROR;}

    DPRINT("receiving file length\n");
    /*file length has not been received yet*/
    char * buff = (char*)(malloc(1 * sizeof(uint32_t)));
    recvAll(acceptedSocket, buff, 1*sizeof(uint32_t));
    //recv(acceptedSocket, buff, 1*sizeof(long), 0);
    *fileLength = ntohl(  *((long*)(buff)));
    DPRINT("received file length %ld\n", *fileLength);
    *inFile = (char*)(malloc( *fileLength *sizeof(char)));

    DPRINT("receiving actual ciphertext itself\n");

    /*signal to techrypt that techdec is ready
    char ack = 'Y';
    send(acceptedSocket, &ack, sizeof(ack), 0);
    */

    /*receive the ciphertext*/
    recvAll(acceptedSocket, *inFile, *fileLength);

    return NONE;
}
 
int recvAll(int socket, char* buff, long len){
    long recvdAmt;
    long totalRecvd = 0;

    while(totalRecvd != len){
	DPRINT("receiving %ld of %ld", totalRecvd, len);
	recvdAmt = recv(socket, (buff+totalRecvd), len-totalRecvd, 0);
	if(-1 == recvdAmt ){
	    continue;
	}
	totalRecvd += recvdAmt;
    }
}

int verifyMac(char* key, int keyLength, char* inFile, long fileLength, int
	macLength){
    int err;
    char* mac;

    err = hmac(key, keyLength, inFile, fileLength - macLength,  &mac,
	    &macLength); checkErr(err, "HMAC computation error");
    if( 0 != memcmp(mac, inFile+fileLength-macLength, macLength)){
	DPRINT("doesn't match!\n");
	return VERIFY_MAC_ERROR;
    }
    return NONE;
}
