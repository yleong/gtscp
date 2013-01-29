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

int sendFile(char* outFile, long fileLength, char* mac, int macLength, char*
	ipAddr, int port);
int sendAll(int socket, char* buff, long len);
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
	DPRINT("sending file to remote host\n");
	err = sendFile(outFile, fileLength, mac, macLength, ipAddr, port);
	checkErr(err, "File send error");
    } else if(L_LOCAL == opt){
	DPRINT("writing file locally\n");
	err = writeFile(fileName, outFile, fileLength, mac, macLength, opt);
	checkErr(err, "File write error");
    }
    
    return 0;
}


int sendFile(char* outFile, long fileLength, char* mac, int macLength, char*
	ipAddr, int port){ 

    int sendSocket;
    int err, portStrlen;
    char *portStr;
    struct addrinfo *res, *curr;
    struct addrinfo hints;
     
    /*set up the hints to let addrinfo knows what flags to filter etc*/
    /*unused fields should be 0*/
    memset(&hints, 0, sizeof(hints));
    /*ipv4*/
    hints.ai_family = AF_INET; 
    /*TCP is needed to transfer ciphertext reliably*/
    hints.ai_socktype = SOCK_STREAM;
    
    /*Convert port number to string*/
    portStrlen = ceil(log10((float)(port))) + 1; /* 1 for \0*/
    portStr = (char *)(malloc(portStrlen * sizeof(char)));
    sprintf(portStr, "%d", port);

    err = getaddrinfo(ipAddr,portStr, &hints, &res);
    if(err){return GETADDR_ERROR;}

    /*get a connected socket out of list: res*/
    err = -1;
    curr = res;
    while(NULL != curr){
	sendSocket = socket((*curr).ai_family, (*curr).ai_socktype,
			    (*curr).ai_protocol);
	if(-1 != sendSocket){
	    //err = bind(sendSocket, (*curr).ai_addr, (*curr).ai_addrlen);
	    err = connect(sendSocket, (*curr).ai_addr, (*curr).ai_addrlen);
	}
	if(-1 != err){
	    /*successfully connected*/
	    break;
	}
	/*try the next one*/
	close(sendSocket);
	curr = (*curr).ai_next;
    }

    /*exhausted res but still no available sockets*/
    if(NULL == curr){
	return NO_SOCK_ERROR;
    }
    freeaddrinfo(res);

    /*attempt to send all the ciphertext*/
    uint32_t length = htonl(fileLength + macLength);
    DPRINT("sending the file length now\n");
    sendAll(sendSocket, (char*)(&length), sizeof(length) );

    char ack = 0;
    //while(-1 != recv(sendSocket, &ack, sizeof(ack), 0) && 'Y' != ack);
    DPRINT("sending the ciphertext now\n");
    sendAll(sendSocket, outFile, fileLength);
    sendAll(sendSocket, mac, macLength);

    close(sendSocket);
    
    return NONE;
}
int sendAll(int socket, char* buff, long len){
    long sentAmt;
    long totalSent = 0;

    while(totalSent != len){
	DPRINT("sending %ld of %ld", totalSent, len);
	sentAmt = send(socket, (buff+totalSent), len-totalSent, 0);
	if(-1 == sentAmt ){
	    continue;
	}
	totalSent += sentAmt;
    }
}
