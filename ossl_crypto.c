#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "crypto_if.h"

static const char *ossl_init(void)
{
	ERR_load_crypto_strings();
	return "openssl";
}

static unsigned long ossl_encrypt(void *key, int keylen, void *iv,
			void *pt, void *ct, int tlen)
{
	EVP_CIPHER_CTX ctx;
	int outlen1, outlen2;
	unsigned char hkey[16];

	if (EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(),
			NULL, key, keylen, 5, hkey, NULL) != 16) return 1UL;
	if (!EVP_EncryptInit(&ctx, EVP_aes_128_cbc(), hkey, iv))
		return ERR_get_error();
	if (!EVP_EncryptUpdate(&ctx, ct, &outlen1, pt, tlen))
		return ERR_get_error();
	if (!EVP_EncryptFinal(&ctx, ct + outlen1, &outlen2))
		return ERR_get_error();
	if (outlen1 + outlen2 != tlen) {
		printf("enc tlen =%d outlen1=%d outlen2=%d\n",
			tlen, outlen1, outlen2);
		// return 1UL;
	}
	return 0UL;
}

static unsigned long ossl_decrypt(void *key, int keylen, void *iv,
			void *ct, void *pt, int tlen)
{
	EVP_CIPHER_CTX ctx;
	int outlen1, outlen2;
	unsigned char hkey[16];

	if (EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(),
			NULL, key, keylen, 5, hkey, NULL) != 16) return 1UL;
	if (!EVP_DecryptInit(&ctx, EVP_aes_128_cbc(), hkey, iv))
		return ERR_get_error();
	if (!EVP_DecryptUpdate(&ctx, ct, &outlen1, pt, tlen))
		return ERR_get_error();
	if (!EVP_DecryptFinal(&ctx, ct + outlen1, &outlen2))
		return ERR_get_error();
	if (outlen1 + outlen2 != tlen) {
		printf("dec tlen =%d outlen1=%d outlen2=%d\n",
			tlen, outlen1, outlen2);
		// return 1UL;
	}
	return 0UL;
}

static unsigned long ossl_hash(void *pt, int tlen, void *tag, int *taglen)
{
	SHA_CTX sctx;

	if (!SHA1_Init(&sctx)) return ERR_get_error();
	if (!SHA1_Update(&sctx, pt, tlen)) return ERR_get_error();
	if (!SHA1_Final(tag, &sctx)) return ERR_get_error();
	*taglen = 20;
	return 0UL;
}

static unsigned long ossl_hmac(void *pt, int tlen, void *key, int keylen,
			void *tag, int *taglen)
{
	if (!HMAC(EVP_sha1(), key, keylen, pt, tlen,
				tag, (unsigned int *)taglen))
			return ERR_get_error();
	return 0UL;
}

static const char *ossl_errstr(unsigned long err)
{
	return ERR_error_string(err, NULL);
}

struct crypto_interface ossl_crypto_if = {
	.init		= ossl_init,
	.encrypt	= ossl_encrypt,
	.decrypt	= ossl_decrypt,
	.hash		= ossl_hash,
	.hmac		= ossl_hmac,
	.errstr		= ossl_errstr,
};
