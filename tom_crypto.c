#include <tomcrypt.h>

#include "crypto_if.h"

static unsigned long tom_encrypt(void *key, int keylen, void *iv,
			void *pt, void *ct, int tlen)
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

static unsigned long tom_decrypt(void *key, int keylen, void *iv,
			void *ct, void *pt, int tlen)
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

static unsigned long tom_hash(void *pt, int tlen, void *tag, int *taglen)
{
	int index, rc;
	unsigned long ltaglen = *taglen;

	if ((index = register_hash(&sha1_desc)) == -1)
		return CRYPT_INVALID_HASH;
	rc = hash_memory(index, pt, tlen, tag, &ltaglen);
	*taglen = ltaglen;
	return rc;
}

static unsigned long tom_hmac(void *key, int keylen,
			void *pt, int tlen, void *tag, int *taglen)
{
	int index, rc;
	unsigned long ltaglen = *taglen;

	if (keylen != 20) return CRYPT_INVALID_KEYSIZE;
	if ((index = register_hash(&sha1_desc)) == -1)
		return CRYPT_INVALID_HASH;
	rc = hmac_memory(index, key, keylen, pt, tlen, tag, &ltaglen);
	*taglen = ltaglen;
	return rc;
}

static const char *tom_errstr(unsigned long err)
{
	return error_to_string((int)err);
}

struct crypto_interface tom_crypto_if = {
	.name		= "tomcrypt",
	.encrypt	= tom_encrypt,
	.decrypt	= tom_decrypt,
	.hash		= tom_hash,
	.hmac		= tom_hmac,
	.errstr		= tom_errstr,
};
