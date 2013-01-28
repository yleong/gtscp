#include <stdio.h>
#include <stdlib.h>
#include "option.h"
#include <string.h>

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
/*ipAddress parameter can be NULL since techdec does not use it.*/
int parseArgs(int argc, char** argv, 
	      char** fileName, char** ipAddress, int* port){
    /*for reference
    "usage: techrypt < input file > [-d < IP-addr:port >][-l ]"
    "usage: techdec < filename >  [-d < port >][-l] "
    */

    int isTechDec = (ipAddress == NULL);
    int option;

    if( (argc <= 1) ||  (argc > 4)){
	return NUM_ARGS_ERROR;
    }

    /* argc = 2, 3, 4*/
    *fileName = argv[1];
    DPRINT("fileName: %s ", *fileName);

    if(argc >= 3){

	/*In case of daemon*/
	if(strcmp("-d", argv[2]) == 0){
	    option = ((isTechDec) ? D_DAEMON : D_SEND);
	    if(argc == 4){ /*get ipaddr and port num*/
		if(!isTechDec){
		    char* delimPos = strchr(argv[3], ':');
		    if(NULL == delimPos){ return STRCHR_ERROR;}
		    *delimPos = '\0';
		    *ipAddress = argv[3];
		    *port = atoi((delimPos+ 1));
		    DPRINT("ip: %s:%d ", *ipAddress, *port);
		} else{
		    *port = atoi(argv[3]);
		    DPRINT("port: %d ", *port);
		}
		if(0 == *port){ return PORT_ERROR;}
	    } else{
		return MISSING_IPPORT_ERROR; 
	    }

	/*In case of local*/
	} else if(strcmp("-l", argv[2]) == 0){
	    option = L_LOCAL;
	    if(argc != 3){
		return ERROR;
	    }
	} else{
	    return UNKNOWN_OPT_ERROR;
	}
    } else if(argc == 2){
	option = L_LOCAL; /* this is implied*/
    }

    return NONE;
}

int checkErr(int err, char* msg){
    if(NONE != err){
	printf("%s\n", msg);
	exit(err);
    }
}
