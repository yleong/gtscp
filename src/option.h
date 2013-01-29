/*Enumeration for the command line options*/
/*Also, defines constants to use*/
#ifndef OPTION_H
#define OPTION_H
enum option{ D_SEND, D_DAEMON, L_LOCAL, NONE, ERROR=71, STRCHR_ERROR=23,
    NUM_ARGS_ERROR=29, MISSING_IPPORT_ERROR=31, UNKNOWN_OPT_ERROR = 37,
    PORT_ERROR=41, GCRYPT_VERSION_ERROR=43, KEY_DERIVE_ERROR=47,
    FOPEN_ERROR=42, OUT_FILE_EXISTS_ERROR=33, CIPHER_OPEN_ERROR=13,
    CIPHER_SETKEY_ERROR=17, CIPHER_SETCTR_ERROR=19, CIPHER_ENCRYPT_ERROR=51,
    MD_OPEN_ERROR=53, MD_SETKEY_ERROR=57, MD_WRITE_ERROR=59,
    VERIFY_MAC_ERROR=62, GETADDR_ERROR=67, NO_SOCK_ERROR=73}; 
#define HMAC_LENGTH (32)
#define DEBUG (0)
#define DPRINT if(DEBUG)printf
#endif
