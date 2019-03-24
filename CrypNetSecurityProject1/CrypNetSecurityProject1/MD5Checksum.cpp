#include "MD5Checksum.h"


unsigned char *getMd5Hash(unsigned char *data, size_t dataLen, int *mdLen) {
	unsigned char *md = NULL;
	EVP_MD_CTX *ctx = NULL;
	const EVP_MD *mdType = EVP_md5();

	*mdLen = EVP_MD_size(mdType);

	md = (unsigned char *)malloc(*mdLen);
	ctx = EVP_MD_CTX_create();

	EVP_MD_CTX_init(ctx);
	EVP_DigestInit_ex(ctx, mdType, NULL);
	EVP_DigestUpdate(ctx, data, dataLen);
	EVP_DigestFinal_ex(ctx, md, NULL);
	EVP_MD_CTX_cleanup(ctx);
	EVP_MD_CTX_destroy(ctx);
	return md;
}