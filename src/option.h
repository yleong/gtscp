/*Enumeration for the command line options*/
/*Also, defines constants to use*/
#ifndef OPTION_H
#define OPTION_H
enum option{ D_SEND, D_DAEMON, L_LOCAL, NONE, ERROR=-1, MAC_MISMATCH=62,
    STRCHR_ERROR, NUM_ARGS_ERROR, MISSING_IPPORT_ERROR, UNKNOWN_OPT_ERROR,
    PORT_ERROR, GCRYPT_VERSION_ERROR, KEY_DERIVE_ERROR, FOPEN_ERROR=42,
    OUT_FILE_EXISTS_ERROR=33};
#define HMAC_LENGTH (256)
#define DEBUG (1)
#define DPRINT if(DEBUG)printf
#endif
