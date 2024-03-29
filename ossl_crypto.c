/*
Copyright (c) 2013 Eugene Crosser

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must
    not claim that you wrote the original software. If you use this
    software in a product, an acknowledgment in the product documentation
    would be appreciated but is not required.

    2. Altered source versions must be plainly marked as such, and must
    not be misrepresented as being the original software.

    3. This notice may not be removed or altered from any source
    distribution.
*/

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

static unsigned long ossl_encrypt(const void *key, const size_t keylen, void *iv,
			const void *pt, void *ct, const size_t tlen)
{
	AES_KEY akey;

	if (AES_set_encrypt_key(key, keylen*8, &akey))
		return ERR_get_error();
	AES_cbc_encrypt(pt, ct, tlen, &akey, iv, AES_ENCRYPT);
	return 0UL;
}

static unsigned long ossl_decrypt(const void *key, const size_t keylen, void *iv,
			const void *ct, void *pt, const size_t tlen)
{
	AES_KEY akey;

	if (AES_set_decrypt_key(key, keylen*8, &akey))
		return ERR_get_error();
	AES_cbc_encrypt(ct, pt, tlen, &akey, iv, AES_DECRYPT);
	return 0UL;
}

static unsigned long ossl_hash(const void *pt, const size_t tlen,
			void *tag, size_t *taglen)
{
	SHA_CTX sctx;

	if (!SHA1_Init(&sctx)) return ERR_get_error();
	if (!SHA1_Update(&sctx, pt, tlen)) return ERR_get_error();
	if (!SHA1_Final(tag, &sctx)) return ERR_get_error();
	*taglen = SHA_DIGEST_LENGTH;
	return 0UL;
}

static unsigned long ossl_hmac(const void *key, size_t const keylen,
			const void *pt, const size_t tlen,
			void *tag, size_t *taglen)
{
#if 0
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

static const char *ossl_errstr(const unsigned long err)
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
