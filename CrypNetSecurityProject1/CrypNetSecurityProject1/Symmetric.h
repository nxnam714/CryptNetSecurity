#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

int stringFromFile(char filename[], const char type[], char **buff);
unsigned char *DES_encrypt(EVP_CIPHER_CTX *en, unsigned char *plaintext, int *plain_len);
char *DES_decrypt(EVP_CIPHER_CTX *de, unsigned char *ciphertext, int *cipher_len);
