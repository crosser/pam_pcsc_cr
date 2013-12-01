#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "authobj.h"
#include "crypto.h"

int main(int argc, char *argv[])
{
	const char *id = "testuser";
	const char *pass = "testpassword";
	const char *nonce = "1";
	unsigned char secret[] = {0xb4, 0x62, 0xf2, 0x60, 0x87,
					0x78, 0x16, 0x87, 0xde, 0xce,
					0x80, 0x09, 0x24, 0x0b, 0x93,
					0xfc, 0xa0, 0xfc, 0x56, 0x56};
	const unsigned char *payload = (unsigned char *)
					"To authorize or not to authorize?";
	int i;
	struct _auth_obj ao;
	struct _auth_obj nao;

	if (argc == 2 && strlen(argv[1]) == 40 &&
			strspn(argv[1], "0123456789abcdefABCDEF") == 40) {
		for (i = 0; i < sizeof(secret); i++)
			sscanf(&argv[1][i*2], "%2hhx", &secret[i]);
	}
	ao = new_authobj(id, pass, nonce, secret, sizeof(secret),
			payload, strlen((char *)payload));
	printf("new_authobj err=%s\n", ao.err?ao.err:"<no error>");
	printf("data(%d):", ao.datasize);
	for (i = 0; i < ao.datasize; i++) printf(" %02x", ao.data[i]);
	printf("\npayload(%d): \"%.*s\"\n", ao.paylsize, ao.paylsize,
		ao.payload?(char*)ao.payload:"");
	if (ao.err) {
		if (ao.buffer) free(ao.buffer);
		return 1;
	}

	nao = verify_authobj(id, pass, nonce, nonce, ao.data, ao.datasize);
	printf("verify_authobj err=%s\n", nao.err?nao.err:"<no error>");
	printf("data(%d):", nao.datasize);
	for (i = 0; i < nao.datasize; i++) printf(" %02x", nao.data[i]);
	printf("\npayload(%d): \"%.*s\"\n", nao.paylsize, nao.paylsize,
		nao.payload?(char*)nao.payload:"");
	if (nao.err) {
		if (nao.buffer) free(nao.buffer);
		return 1;
	}
	if (ao.paylsize != nao.paylsize ||
			memcmp(ao.payload, nao.payload, ao.paylsize)) {
		printf("payload does not match");
		return 1;
	}

	if (ao.buffer) free(ao.buffer);
	if (nao.buffer) free(nao.buffer);
	return 0;
}
