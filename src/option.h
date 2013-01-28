/*Enumeration for the command line options*/
/*Also, defines constants to use*/
#ifndef OPTION_H
#define OPTION_H
enum option{ D_SEND, D_DAEMON, L_LOCAL, NONE, ERROR=-1, MAC_MISMATCH=62};
#define HMAC_LENGTH (256)
#endif
