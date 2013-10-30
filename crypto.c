#include <assert.h>
#include "crypto.h"
#include "crypto_if.h"

extern struct crypto_interface ossl_crypto_if;
extern struct crypto_interface tom_crypto_if;

static struct crypto_interface *ifs[] = {
#ifdef HAVE_OPENSSL
	&ossl_crypto_if,
#endif
#ifdef HAVE_TOMCRYPT
	&tom_crypto_if,
#endif
	(void*)0,
};
#define MAX_IF (sizeof(ifs)/sizeof(struct crypto_interface *)-2)

static int which = 0;

int select_crypto_if(int ifno)
{
	if (ifno < 0 || ifno > MAX_IF) return -1;
	which = ifno;
	return 0;
}

static unsigned char iv[16] = {0};

unsigned long encrypt(void *key, int keylen, void *pt, void *ct, int tlen)
{
	assert(keylen == 16);
	return ifs[which]->encrypt(key, keylen, iv, pt, ct, tlen);
}

unsigned long decrypt(void *key, int keylen, void *ct, void *pt, int tlen)
{
	assert(keylen == 16);
	return ifs[which]->decrypt(key, keylen, iv, ct, pt, tlen);
}

unsigned long hash(void *pt, int tlen, void *tag, int *taglen)
{
	assert(*taglen == 20);
	return ifs[which]->hash(pt, tlen, tag, taglen);
}

unsigned long hmac(void *key, int keylen, void *pt, int tlen, void *tag, int *taglen)
{
	assert(keylen == 20);
	assert(*taglen == 20);
	return ifs[which]->hmac(key, keylen, pt, tlen, tag, taglen);
}

const char *crypto_errstr(unsigned long err)
{
	return ifs[which]->errstr(err);
}
