#ifndef _CRYPTO_IF_H
#define _CRYPTO_IF_H

struct crypto_interface {
	char *name;
	int (*encrypt)(void *pt, int ptlen, void *key, int keylen,
			void *ct, int *ctlen);
	int (*decrypt)(void *ct, int ctlen, void *key, int keylen,
			void *pt, int *ptlen);
	int (*hash)(void *pt, int ptlen, void *tag, int *taglen);
	int (*hmac)(void *ct, int ctlen, void *key, int keylen,
			void *tag, int *taglen);
};

#endif
