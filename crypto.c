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
#include <stddef.h>
#include <assert.h>
#include "crypto.h"
#include "crypto_if.h"

extern struct crypto_interface ossl_crypto_if;
extern struct crypto_interface tom_crypto_if;
extern struct crypto_interface gnu_crypto_if;

static struct crypto_interface *ifs[] = {
#ifdef HAVE_OPENSSL
	&ossl_crypto_if,
#endif
#ifdef HAVE_TOMCRYPT
	&tom_crypto_if,
#endif
#ifdef HAVE_GCRYPT
	&gnu_crypto_if,
#endif
	(struct crypto_interface *)0,
};
#define MAX_IF (int)(sizeof(ifs)/sizeof(struct crypto_interface *)-2)

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

unsigned long encrypt(const void *key, const size_t keylen, const void *pt, void *ct, const size_t tlen)
{
	unsigned char iv[16] = INITIV;

	assert(keylen == 16);
	return ifs[which]->encrypt(key, keylen, iv, pt, ct, tlen);
}

unsigned long decrypt(const void *key, const size_t keylen, const void *ct, void *pt, const size_t tlen)
{
	unsigned char iv[16] = INITIV;

	assert(keylen == 16);
	return ifs[which]->decrypt(key, keylen, iv, ct, pt, tlen);
}

unsigned long hash(const void *pt, const size_t tlen, void *tag, size_t *taglen)
{
	assert(*taglen == 20);
	return ifs[which]->hash(pt, tlen, tag, taglen);
}

unsigned long hmac(const void *key, const size_t keylen, const void *pt, const size_t tlen, void *tag, size_t *taglen)
{
	assert(*taglen == 20);
	return ifs[which]->hmac(key, keylen, pt, tlen, tag, taglen);
}

const char *crypto_errstr(const unsigned long err)
{
	return ifs[which]->errstr(err);
}
