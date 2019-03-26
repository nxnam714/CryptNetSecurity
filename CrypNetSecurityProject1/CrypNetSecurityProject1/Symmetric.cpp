#include "Symmetric.h"

int stringFromFile(char filename[], const char type[], char **buff)
{
	unsigned char *str = NULL;

	/* Open file */
	FILE *fp;

	fp = fopen(filename, type);

	/* Check if file is readable */
	if (!fp)
	{
		printf("ERROR. Couldn't read file.\n");
		exit(1);
	}

	// Get the end position of the file
	fseek(fp, 0, SEEK_END);
	int length = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// Allocate memory for the string
	str = (unsigned char*)malloc(length);

	fread(str, length, 1, fp);

	fclose(fp);

	(*buff) = (char *)str;
	return length;
}


unsigned char *DES_encrypt(EVP_CIPHER_CTX *en, unsigned char *plaintext, int *plain_len)
{
	/* Allocate memory from size of plaintext */
	int cipher_len = *plain_len + 8;

	int tmp;

	unsigned char *ciphertext = (unsigned char *)malloc(cipher_len);

	/* Encrypt the plaintext to ciphertext */
	EVP_EncryptUpdate(en, ciphertext, &cipher_len, plaintext, *plain_len);

	EVP_EncryptFinal_ex(en, ciphertext + cipher_len, &tmp);

	*plain_len = cipher_len + tmp;

	return ciphertext;
}

char *DES_decrypt(EVP_CIPHER_CTX *de, unsigned char *ciphertext, int *cipher_len)
{
	/* Allocate memory for plaintext from size of ciphertext */
	int plain_len = *cipher_len;

	int tmp;

	unsigned char *plaintext = (unsigned char *)malloc(plain_len);

	/* Decrypt the ciphertext */
	EVP_DecryptUpdate(de, plaintext, &plain_len, ciphertext, *cipher_len);

	EVP_DecryptFinal_ex(de, plaintext + plain_len, &tmp);

	*cipher_len = plain_len + tmp;

	return (char *)plaintext;
}