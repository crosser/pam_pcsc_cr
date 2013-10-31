#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
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
	AES_KEY akey;

	if (AES_set_encrypt_key(key, keylen*8, &akey))
		return ERR_get_error();
	AES_cbc_encrypt(pt, ct, tlen, &akey, iv, AES_ENCRYPT);
	return 0UL;
}

static unsigned long ossl_decrypt(void *key, int keylen, void *iv,
			void *ct, void *pt, int tlen)
{
	AES_KEY akey;

	if (AES_set_decrypt_key(key, keylen*8, &akey))
		return ERR_get_error();
	AES_cbc_encrypt(ct, pt, tlen, &akey, iv, AES_DECRYPT);
	return 0UL;
}

static unsigned long ossl_hash(void *pt, int tlen, void *tag, int *taglen)
{
	SHA_CTX sctx;

	if (!SHA1_Init(&sctx)) return ERR_get_error();
	if (!SHA1_Update(&sctx, pt, tlen)) return ERR_get_error();
	if (!SHA1_Final(tag, &sctx)) return ERR_get_error();
	*taglen = SHA_DIGEST_LENGTH;
	return 0UL;
}

static unsigned long ossl_hmac(void *key, int keylen, void *pt, int tlen,
			void *tag, int *taglen)
{
#if 1
	HMAC_CTX hctx;

	HMAC_CTX_init(&hctx);
	if (!HMAC_Init_ex(&hctx, key, keylen, EVP_sha1(), NULL))
		return ERR_get_error();
	if (!HMAC_Update(&hctx, pt, tlen)) return ERR_get_error();
	if (!HMAC_Final(&hctx, tag, (unsigned int *)taglen))
		return ERR_get_error();
	HMAC_CTX_cleanup(&hctx);
#else
	if (HMAC(EVP_sha1(), key, keylen, pt, tlen,
				tag, (unsigned int *)taglen) != tag)
		return ERR_get_error();
#endif
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
