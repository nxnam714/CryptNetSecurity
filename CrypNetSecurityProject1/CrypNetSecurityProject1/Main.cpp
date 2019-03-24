#include <iostream>
#include <fstream>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "Addition.h"
#include "Asymmetric.h"
#include "Symmetric.h"
#include "Main.h"


#define SYMMETRIC_ENCODE	10
#define SYMMETRIC_DECODE	11
#define RSA_CREATE			20
#define RSA_ENCODE			21
#define RSA_DECODE			22
#define STREGAN_ENCODE		30
#define STREGAN_DECODE		31


using namespace std;


int main(int argc, char *argv[])
{
	int tasks = 0;
	if (argc > 1) {
		sscanf(argv[1], "%d", &tasks);
	}
	else
	{
		system("pause");
		return 0;
	}
	switch (tasks)
	{
	case STREGAN_ENCODE:
	{
		Mat image = imread(argv[3]);
		steganography_encode(argv[2], image, argv[4]);
		break;
	}
	case STREGAN_DECODE:
	{
		Mat cipherImage = imread(argv[2]);
		steganography_decode(cipherImage, argv[3]);
	}
	case RSA_CREATE:
	{
		RSA *keypair = RSA_generate_key(KEY_LENGTH, PUBLIC_EXPONENT, NULL, NULL);

		create_RSA(keypair, PRIVATE_KEY_PEM, argv[2]);
		create_RSA(keypair, PUBLIC_KEY_PEM, argv[3]);

		RSA_free(keypair);
		break;
	}
	case RSA_ENCODE:
	{
		RSA *private_key = NULL;
		RSA *public_key = NULL;
		FILE  *fp = NULL;

		char message[KEY_LENGTH / 8];
		char *encrypt = NULL;
		char *decrypt = NULL;

		fp = fopen(argv[2], "r");
		fgets(message, KEY_LENGTH / 8, fp);
		fclose(fp);

		fp = fopen(argv[3], "rb");
		PEM_read_RSAPrivateKey(fp, &private_key, NULL, NULL);
		fclose(fp);

		fp = fopen(argv[4], "rb");
		PEM_read_RSAPublicKey(fp, &public_key, NULL, NULL);
		fclose(fp);

		encrypt = (char*)malloc(RSA_size(public_key));
		int encrypt_length = public_encrypt(strlen(message) + 1, (unsigned char*)message, (unsigned char*)encrypt, public_key, RSA_PKCS1_OAEP_PADDING);
		if (encrypt_length == -1) {
			LOG("An error occurred in public_encrypt() method");
		}
		LOG("Data has been encrypted.");

		create_encrypted_file(encrypt, public_key);
		LOG("Encrypted file has been created.");

		RSA_free(private_key);
		RSA_free(public_key);
		free(encrypt);
		break;
	}
	case RSA_DECODE:
	{
		RSA *private_key = NULL;
		FILE  *fp = NULL;
		char *encrypt = NULL;
		char *decrypt = NULL;

		fp = fopen(argv[2], "rb");
		PEM_read_RSAPrivateKey(fp, &private_key, NULL, NULL);
		fclose(fp);

		ifstream file(argv[3], ios::in | ios::binary | ios::ate);
		int encrypt_length = file.tellg();
		file.seekg(0, ios::beg);

		encrypt = (char*)malloc(RSA_size(private_key));
		file.read(encrypt, encrypt_length);

		decrypt = (char *)malloc(encrypt_length);
		int decrypt_length = private_decrypt(encrypt_length, (unsigned char*)encrypt, (unsigned char*)decrypt, private_key, RSA_PKCS1_OAEP_PADDING);
		if (decrypt_length == -1) {
			LOG("An error occurred in private_decrypt() method");
		}
		LOG("Data has been decrypted.");

		FILE *decrypted_file = fopen(argv[4], "w");
		fwrite(decrypt, sizeof(*decrypt), decrypt_length - 1, decrypted_file);
		fclose(decrypted_file);
		LOG("Decrypted file has been created.");

		RSA_free(private_key);
		free(encrypt);
		free(decrypt);
		LOG("OpenSSL_RSA has been finished.");
		break;
	}
	default:
		break;
	}
	cout << "Hello World\n";
	system("pause");
	return 0;
}