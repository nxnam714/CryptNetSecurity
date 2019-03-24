#include<openssl/evp.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

unsigned char *getMd5Hash(unsigned char *data, size_t dataLen, int *mdLen);