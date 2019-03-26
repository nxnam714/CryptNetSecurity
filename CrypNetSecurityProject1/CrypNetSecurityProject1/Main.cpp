#include <iostream>
#include <fstream>
#include <time.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "Addition.h"
#include "Asymmetric.h"
#include "Symmetric.h"
#include "MD5Checksum.h"


#define SYMMETRIC_ENCODE	10
#define SYMMETRIC_DECODE	11
#define RSA_CREATE			20
#define RSA_ENCODE			21
#define RSA_DECODE			22
#define STREGAN_ENCODE		30
#define STREGAN_DECODE		31
#define MD5_CHECKSUM		40

#define DATA_LENGTH			2048


using namespace std;


int main(int argc, char *argv[])
{
	clock_t start_t, end_t, total_t;

	int tasks = 0;
	if (argc > 1) {
		sscanf(argv[1], "%d", &tasks);
	}
	else
	{
		system("pause");
		return 0;
	}

	start_t = clock();

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
		break;
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

		fp = fopen(argv[2], "rb");
		//fgets(message, KEY_LENGTH / 8, fp);
		fseek(fp, 0, SEEK_END);
		int inlength = ftell(fp);
		rewind(fp);
		fread(message, sizeof(char), inlength, fp);
		fclose(fp);

		fp = fopen(argv[3], "rb");
		PEM_read_RSAPrivateKey(fp, &private_key, NULL, NULL);
		fclose(fp);

		fp = fopen(argv[4], "rb");
		PEM_read_RSAPublicKey(fp, &public_key, NULL, NULL);
		fclose(fp);

		encrypt = (char*)malloc(RSA_size(public_key));
		int encrypt_length = public_encrypt(inlength, (unsigned char*)message, (unsigned char*)encrypt, public_key, RSA_PKCS1_OAEP_PADDING);
		if (encrypt_length == -1) 
		{
			LOG("An error occurred in public_encrypt() method");
		}
		LOG("Data has been encrypted.");

		create_encrypted_file(encrypt, public_key, argv[5]);
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
		if (decrypt_length == -1) 
		{
			LOG("An error occurred in private_decrypt() method");
		}
		LOG("Data has been decrypted.");

		FILE *decrypted_file = fopen(argv[4], "wb");
		fwrite(decrypt, sizeof(*decrypt), decrypt_length - 1, decrypted_file);
		fclose(decrypted_file);
		LOG("Decrypted file has been created.");

		RSA_free(private_key);
		free(encrypt);
		free(decrypt);
		LOG("OpenSSL_RSA has been finished.");
		break;
	}
	case MD5_CHECKSUM:
	{
		FILE  *fp = NULL;
		char *plaintext = NULL, *decryptedtext = NULL;
		unsigned char *md1, *md2;
		int mdLen1, mdLen2 = 0;

		//memset(&plainttext, 0, DATA_LENGTH);
		//memset(&decryptedtext, 0, DATA_LENGTH);

		fp = fopen(argv[2], "rb");
		//fgets(plainttext, DATA_LENGTH, fp);
		fseek(fp, 0, SEEK_END);
		int plainlength = ftell(fp);
		rewind(fp);
		plaintext = (char *)malloc((plainlength) * sizeof(char));
		fread(plaintext, sizeof(char), plainlength, fp);
		fclose(fp);

		fp = fopen(argv[3], "rb");
		fseek(fp, 0, SEEK_END);
		int decryptedlength = ftell(fp);
		rewind(fp);
		decryptedtext = (char *)malloc((decryptedlength) * sizeof(char));
		fread(decryptedtext, sizeof(char), decryptedlength, fp);
		//fgets(decryptedtext, DATA_LENGTH, fp);
		fclose(fp);

		if (plainlength != decryptedlength)
		{
			cout << "FALSE\n";
			break;
		}
		md1 = getMd5Hash((unsigned char *)plaintext, plainlength, &mdLen1);
		md2 = getMd5Hash((unsigned char *)decryptedtext, decryptedlength, &mdLen2);

		//cout << memcmp(plainttext, decryptedtext, DATA_LENGTH) << endl;

		if ((mdLen1 == mdLen2) && !memcmp(md1, md2, mdLen1))
		{
			cout << "OK\n";
		}
		else
		{
			cout << "FALSE\n";
		}
		free(md2);
		free(md1);
		break;
	}
	case SYMMETRIC_ENCODE:
	{
		char *key = NULL;
		char *plain = NULL;
		unsigned char *ciphertext;

		int input_len = stringFromFile(argv[2], "rb", &plain);
		stringFromFile(argv[3], "rb", &key);


		/* Initialize the EVP key */
		EVP_CIPHER_CTX en;

		EVP_CIPHER_CTX_init(&en);

		EVP_EncryptInit_ex(&en, EVP_des_ecb(), NULL, (unsigned char *)key, NULL);

		/* Encrypt */
		ciphertext = DES_encrypt(&en, (unsigned char *)plain, &input_len);
		
		/* Write ciphertext to file */
		FILE *inf = fopen(argv[4], "wb");

		fwrite(ciphertext, sizeof(char), (input_len) * sizeof(char), inf);

		fclose(inf);

		/* Free the EVP key */
		EVP_CIPHER_CTX_cleanup(&en);

		/* Free variables */
		free(key);
		free(plain);
		free(ciphertext);
		break;
	}
	case SYMMETRIC_DECODE:
	{
		char *key = NULL;
		char *plaintext;
		unsigned char *cipher = NULL;

		int cipher_len;

		stringFromFile(argv[2], "rb", &key);

		/* Get cipher text from file*/
		cipher_len = stringFromFile(argv[3], "rb", (char**)&cipher);

		/* Initialize the EVP key */
		EVP_CIPHER_CTX ctx;

		EVP_CIPHER_CTX_init(&ctx);

		/* Initialize key and iv */
		EVP_DecryptInit_ex(&ctx, EVP_des_ecb(), NULL, (unsigned char *)key, NULL);

		/* Decrypt the ciphertext into plaintext */
		plaintext = DES_decrypt(&ctx, cipher, &cipher_len);

		/* Write plaintext to file */
		FILE *wf = fopen(argv[4], "wb");
		fwrite(plaintext, sizeof(char), (cipher_len) * sizeof(char), wf);
		fclose(wf);

		/* Free the evp key */
		EVP_CIPHER_CTX_cleanup(&ctx);

		free(key);
		free(plaintext);
		free(cipher);
		break;
	}
	default:
		break;
	}

	end_t = clock();
	total_t = (end_t - start_t);
	printf("Total time taken by CPU: %d\n", total_t);

	//system("pause");
	return 0;
}