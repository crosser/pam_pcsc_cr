#ifndef _CRYPTO_H
#define _CRYPTO_H

int select_crypto_if(const int ifno);
const char *crypto_init(const int ifno);
unsigned long encrypt(const void *key, const int keylen, const void *pt, void *ct, const int tlen);
unsigned long decrypt(const void *key, const int keylen, const void *ct, void *pt, const int tlen);
unsigned long hash(const void *pt, const int tlen, void *tag, int *taglen);
unsigned long hmac(const void *key, const int keylen, const void *pt, const int tlen,
			void *tag, int *taglen);
const char *crypto_errstr(const unsigned long err);

#define HASHSIZE 20
#define CBLKSIZE 16

#endif
