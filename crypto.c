#include "crypto.h"
#include "crypto_if.h"

extern struct crypto_interface ossl_crypto_if;
extern struct crypto_interface tom_crypto_if;

static struct crypto_interface *active = &ossl_crypto_if;

int encrypt(void *pt, int ptlen, void *key, int keylen, void *ct, int *ctlen)
{
	return active->encrypt(pt, ptlen, key, keylen, ct, ctlen);
}

int decrypt(void *ct, int ctlen, void *key, int keylen, void *pt, int *ptlen)
{
	return active->decrypt(ct, ctlen, key, keylen, pt, ptlen);
}

int hash(void *pt, int ptlen, void *tag, int *taglen)
{
	return active->hash(pt, ptlen, tag, taglen);
}

int hmac(void *pt, int ptlen, void *key, int keylen, void *tag, int *taglen)
{
	return active->hmac(pt, ptlen, key, keylen, tag, taglen);
}

