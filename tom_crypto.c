#include <tomcrypt.h>

#include "crypto_if.h"

static int tom_encrypt(void *pt, int ptlen, void *key, int keylen,
			void *ct, int *ctlen)
{
	symmentric_cbc cbc;
	unsigned char iv[16] = {0};
	int index, err;

	if ((index = register_cipher(&aes_desc)) == -1) return -1;
	// if ((index = find_cipher("aes")) == -1) return -1;
	cipher = cipher_descriptor[index];
	if ((err = cbc_start(index, iv, key, keylen, 0, &cbc)) != CRYPT_OK)
		return err;
	if ((err = cbc_encrypt(pt, ct, ptlen, &cbc)) != CRYPT_OK)
		return err;
	if ((err = cbc_done(&cbc)) != CRYPT_OK)
		return err;
	if ((err = unregister_cipher(&aes_desc)) != CRYPT_OK)
		return err;
	return 0;
}

static int tom_decrypt()
{
	return 0;
}

static int tom_hash()
{
	return 0;
}

static int tom_hmac()
{
	return 0;
}

struct crypto_interface tom_crypto_if = {
	.name		= "tomcrypt",
	.encrypt	= tom_encrypt,
	.decrypt	= tom_decrypt,
	.hash		= tom_hash,
	.hmac		= tom_hmac,
};
