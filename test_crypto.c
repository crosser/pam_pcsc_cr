#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "crypto.h"

#define printh(x) printh_f(#x, x, sizeof(x))
void printh_f(char *p, unsigned char *x, size_t l)
{
	int i;
	printf("%s:", p);
	for (i=0; i<l; i++) printf(" %02x", x[i]);
	printf("\n");
}

int test_enc_dec(int iface1, int iface2)
{
	unsigned long err;
	unsigned char pt[48] = "the quick brown fox jumps over a lazy dog";
	unsigned char key[16] = {0x0f,0x65,0xd1,0x3a,0xfe,0xcb,0xc4,0xb9,
				0x52,0xb1,0x60,0xcf,0xe8,0x55,0x6a,0xdd};
	unsigned char ct[64];
	unsigned char re[48];

	printf("%d -> %d\n", iface1, iface2);
	printh(pt);
	printh(key);
	if (select_crypto_if(iface1)) return 1;
	memset(ct, 0xfe, sizeof(ct));
	if ((err = encrypt(key, sizeof(key), pt, ct, sizeof(pt)))) {
		printf("encrypt error: %s\n", crypto_errstr(err));
		return 1;
	}
	printh(ct);
	if (select_crypto_if(iface2)) return 1;
	if ((err = decrypt(key, sizeof(key), ct, re, sizeof(re)))) {
		printf("decrypt error: %s\n", crypto_errstr(err));
		return 1;
	}
	printh(re);
	if (memcmp(pt, re, sizeof(pt))) {
		printf("fail\n");
		return 1;
	}
	return 0;
}

int test_sha(int iface)
{
	unsigned char sha1[20];
	unsigned long err;
	int shalen;
	unsigned char spt[3] = "abc";
	unsigned char sstd[20] = {0xA9,0x99,0x3E,0x36,0x47,0x06,0x81,0x6A,
		0xBA,0x3E,0x25,0x71,0x78,0x50,0xC2,0x6C,0x9C,0xD0,0xD8,0x9D};

	if (select_crypto_if(iface)) return 1;
	shalen = 20;
	if ((err = hash(spt, sizeof(spt), sha1, &shalen))) {
		printf("hash error: %s\n", crypto_errstr(err));
		return 1;
	}
	printf("%d: len=%d ", iface, shalen);
	printh(sha1);
	if (memcmp(sha1, sstd, sizeof(sstd))) {
		printf("fail\n");
		return 1;
	}
	return 0;
}

int test_hmac(int iface)
{
	unsigned char hmac1[20];
	unsigned long err;
	int hmaclen;
	unsigned char hpt[28] = "what do ya want for nothing?";
	unsigned char hkey[4] = "Jefe";
	unsigned char hstd[20] = {0xef,0xfc,0xdf,0x6a,0xe5,0xeb,0x2f,0xa2,
		0xd2,0x74,0x16,0xd5,0xf1,0x84,0xdf,0x9c,0x25,0x9a,0x7c,0x79};

	if (select_crypto_if(iface)) return 1;
	hmaclen = 20;
	if ((err = hmac(hkey, sizeof(hkey), hpt, sizeof(hpt),
						hmac1, &hmaclen))) {
		printf("hash error: %s\n", crypto_errstr(err));
		return 1;
	}
	printf("%d: len=%d ", iface, hmaclen);
	printh(hmac1);
	if (memcmp(hmac1, hstd, sizeof(hstd))) {
		printf("fail\n");
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int rc, maxrc = 0;
	int numifs, i, j;
	const char *name;

	for (numifs = 0; (name = crypto_init(numifs)); numifs++)
		printf("%d: %s\n", numifs, name);
	printf("Testing %d interfaces\n\n", numifs);

	for (i = 0; i < numifs; i++)
		if ((rc = test_sha(i)) > maxrc) maxrc = rc;
	for (i = 0; i < numifs; i++)
		if ((rc = test_hmac(i)) > maxrc) maxrc = rc;
	for (i = 0; i < numifs; i++) for (j = 0; j < numifs; j++)
		if ((rc = test_enc_dec(i,j)) > maxrc) maxrc = rc;
	return maxrc;
}
