#ifndef _CRYPTO_H
#define _CRYPTO_H

int select_crypto_if(int ifno);
const char *crypto_init(int ifno);
unsigned long encrypt(void *key, int keylen, void *pt, void *ct, int tlen);
unsigned long decrypt(void *key, int keylen, void *ct, void *pt, int tlen);
unsigned long hash(void *pt, int tlen, void *tag, int *taglen);
unsigned long hmac(void *key, int keylen, void *pt, int tlen,
			void *tag, int *taglen);
const char *crypto_errstr(unsigned long err);

#endif
