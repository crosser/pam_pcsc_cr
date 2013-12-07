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
#include <tomcrypt.h>

#include "crypto_if.h"

static const char *tom_init(void)
{
	/* nothing to initialize */
	return "tomcrypt";
}

static unsigned long tom_encrypt(const void *key, const int keylen, void *iv,
			const void *pt, void *ct, const int tlen)
{
	symmetric_CBC cbc;
	int index, err;

	if ((index = register_cipher(&aes_desc)) == -1)
		return CRYPT_INVALID_CIPHER;
	if ((err = cbc_start(index, iv, key, keylen, 0, &cbc)) != CRYPT_OK)
		return err;
	err= cbc_encrypt(pt, ct, tlen, &cbc);
	(void)cbc_done(&cbc);
	return err;
}

static unsigned long tom_decrypt(const void *key, const int keylen, void *iv,
			const void *ct, void *pt, const int tlen)
{
	symmetric_CBC cbc;
	int index, err;

	if ((index = register_cipher(&aes_desc)) == -1)
		return CRYPT_INVALID_CIPHER;
	if ((err = cbc_start(index, iv, key, keylen, 0, &cbc)) != CRYPT_OK)
		return err;
	err= cbc_decrypt(ct, pt, tlen, &cbc);
	(void)cbc_done(&cbc);
	return err;
}

static unsigned long tom_hash(const void *pt, const int tlen,
			void *tag, int *taglen)
{
	int index, rc;
	unsigned long ltaglen = *taglen;

	if ((index = register_hash(&sha1_desc)) == -1)
		return CRYPT_INVALID_HASH;
	rc = hash_memory(index, pt, tlen, tag, &ltaglen);
	*taglen = ltaglen;
	return rc;
}

static unsigned long tom_hmac(const void *key, const int keylen,
			const void *pt, const int tlen,
			void *tag, int *taglen)
{
	int index, rc;
	unsigned long ltaglen = *taglen;

	if ((index = register_hash(&sha1_desc)) == -1)
		return CRYPT_INVALID_HASH;
	rc = hmac_memory(index, key, keylen, pt, tlen, tag, &ltaglen);
	*taglen = ltaglen;
	return rc;
}

static const char *tom_errstr(const unsigned long err)
{
	return error_to_string((int)err);
}

struct crypto_interface tom_crypto_if = {
	.init		= tom_init,
	.encrypt	= tom_encrypt,
	.decrypt	= tom_decrypt,
	.hash		= tom_hash,
	.hmac		= tom_hmac,
	.errstr		= tom_errstr,
};
