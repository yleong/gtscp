CFLAGS=-Wall -g
techrypt techdec: techrypt.c techdec.c techutils.c
	cc -o techrypt techrypt.c techutils.c `libgcrypt-config --cflags --libs` -lm
	cc -o techdec techdec.c  techutils.c `libgcrypt-config --cflags --libs` -lm
    
