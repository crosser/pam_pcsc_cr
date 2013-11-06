#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
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

int select_crypto_if(const int ifno)
{
	if (ifno < 0 || ifno > MAX_IF) return -1;
	which = ifno;
	return 0;
}

const char *crypto_init(const int ifno)
{
	if (ifno < 0 || ifno > MAX_IF) return (const char *)0;
	return ifs[ifno]->init();
}

#define INITIV {0}

unsigned long encrypt(const void *key, const int keylen, const void *pt, void *ct, const int tlen)
{
	unsigned char iv[16] = INITIV;

	assert(keylen == 16);
	return ifs[which]->encrypt(key, keylen, iv, pt, ct, tlen);
}

unsigned long decrypt(const void *key, const int keylen, const void *ct, void *pt, const int tlen)
{
	unsigned char iv[16] = INITIV;

	assert(keylen == 16);
	return ifs[which]->decrypt(key, keylen, iv, ct, pt, tlen);
}

unsigned long hash(const void *pt, const int tlen, void *tag, int *taglen)
{
	assert(*taglen == 20);
	return ifs[which]->hash(pt, tlen, tag, taglen);
}

unsigned long hmac(const void *key, const int keylen, const void *pt, const int tlen, void *tag, int *taglen)
{
	assert(*taglen == 20);
	return ifs[which]->hmac(key, keylen, pt, tlen, tag, taglen);
}

const char *crypto_errstr(const unsigned long err)
{
	return ifs[which]->errstr(err);
}
