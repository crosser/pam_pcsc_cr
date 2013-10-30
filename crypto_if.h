#ifndef _CRYPTO_IF_H
#define _CRYPTO_IF_H

struct crypto_interface {
	char *name;
	unsigned long (*encrypt)(void *key, int keylen, void *iv,
				void *pt, void *ct, int tlen);
	unsigned long (*decrypt)(void *key, int keylen, void *iv,
				void *ct, void *pt, int tlen);
	unsigned long (*hash)(void *pt, int tlen, void *tag, int *taglen);
	unsigned long (*hmac)(void *key, int keylen,
				void *pt, int tlen, void *tag, int *taglen);
	const char *(*errstr)(unsigned long err);
};

#endif
