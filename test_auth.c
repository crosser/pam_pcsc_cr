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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "authobj.h"
#include "crypto.h"
#include "pcsc_cr.h"

unsigned char secret[] = {
	0xb4, 0x62, 0xf2, 0x60, 0x87, 0x78, 0x16, 0x87, 0xde, 0xce,
	0x80, 0x09, 0x24, 0x0b, 0x93, 0xfc, 0xa0, 0xfc, 0x56, 0x56
};

static struct _auth_chunk
conjure_key(const unsigned char *challenge, const int challengesize)
{
	struct _auth_chunk ho = {0};
	long rc;
	int keysize = sizeof(ho.data);

	if ((rc = hmac(secret, sizeof(secret), challenge, challengesize,
						&ho.data, &keysize))) {
		ho.err = crypto_errstr(rc);
	} else if (keysize != sizeof(ho.data)) {
		ho.err = "make_key: hash size is wrong";
	}
	return ho;
}

static struct _auth_chunk
token_key(const unsigned char *challenge, const int challengesize)
{
	struct _auth_chunk ho = {0};
	long rc;
	int keysize = sizeof(ho.data);

	if ((rc = pcsc_cr(challenge, challengesize, ho.data, &keysize))) {
		ho.err = pcsc_errstr(rc);
	}
	return ho;
}

int main(int argc, char *argv[])
{
	const char *id = "testuser";
	const char *pass = "testpassword";
	const char *nonce = "1";
	const unsigned char *payload = (unsigned char *)
					"To authorize or not to authorize?";
	int i;
	struct _auth_obj ao;
	struct _auth_obj nao;
	struct _auth_chunk (*fetch_key)(const unsigned char *challenge,
					const int challengesize);

	if (argc == 2 && strlen(argv[1]) == 40 &&
			strspn(argv[1], "0123456789abcdefABCDEF") == 40) {
		for (i = 0; i < sizeof(secret); i++)
			sscanf(&argv[1][i*2], "%2hhx", &secret[i]);
		fetch_key = token_key;
	} else {
		fetch_key = conjure_key;
	}

	ao = authobj(id, pass, NULL, nonce, secret, sizeof(secret),
			payload, strlen((char *)payload),
			NULL, 0, NULL);
	printf("new_authobj err=%s\n", ao.err?ao.err:"<no error>");
	printf("data(%d):", ao.datasize);
	for (i = 0; i < ao.datasize; i++) printf(" %02x", ao.data[i]);
	printf("\npayload(%d): \"%.*s\"\n", ao.paylsize, ao.paylsize,
		ao.payload?(char*)ao.payload:"");
	if (ao.err) {
		if (ao.buffer) free(ao.buffer);
		return 1;
	}

	nao = authobj(id, pass, nonce, nonce, NULL, 0, NULL, 0,
			ao.data, ao.datasize, fetch_key);
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
