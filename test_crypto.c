#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "crypto.h"

unsigned char pt[48] = "the quick brown fox jumps over a lazy dog";
unsigned char key[16] = {
0x0f,0x65,0xd1,0x3a,0xfe,0xcb,0xc4,0xb9,0x52,0xb1,0x60,0xcf,0xe8,0x55,0x6a,0xdd
};

static void usage(const char const *cmd)
{
	fprintf(stderr, "usage: %s\n", cmd);
}

#define printh(p,x) printh_f(p, x, sizeof(x))
void printh_f(char *p, unsigned char *x, size_t l)
{
	int i;
	printf("%s:", p);
	for (i=0; i<l; i++) printf(" %02x", x[i]);
	printf("\n");
}

int main(int argc, char *argv[])
{
	unsigned long err;
	unsigned char ct1[48], re1[48];
	unsigned char sha1[20], sha2[20];
	unsigned char hmac1[20], hmac2[20];

	printf("source: %s\n", pt);
	printh("source", pt);
	printh("key", key);
	if (select_crypto_if(0)) return 1;
	if (err = encrypt(key, sizeof(key), pt, ct1, sizeof(pt)))
		printf("encrypt error: %s\n", crypto_errstr(err));
	printh("ct1", ct1);
	if (err = decrypt(key, sizeof(key), ct1, re1, sizeof(re1)))
		printf("decrypt error: %s\n", crypto_errstr(err));
	printh("re1", re1);
	if (select_crypto_if(1)) return 1;
	return 0;
}
