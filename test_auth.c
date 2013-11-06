#include <stdio.h>
#include <string.h>
#include "authobj.h"

int main(int argc, char *argv[])
{
	const char *id = "testuser";
	const char *pass = "testpassword";
	const char *nonce = "1";
	const unsigned char secret[] = {0x52, 0xf3, 0xbe, 0x1f, 0x3e,
					0x22, 0xa8, 0xee, 0xdf, 0x10,
					0x86, 0xf2, 0x17, 0xd7, 0x21,
					0x9d, 0x08, 0x14, 0x48, 0x38};
	const unsigned char *payload = (unsigned char *)
					"To authorize or not to authorize?";
	unsigned char authobj[512];
	int authsize = sizeof(authobj);
	unsigned char challenge[128];
	int challengesize = sizeof(challenge);
	int rc;
	const unsigned char key[] =    {0xcc, 0x21, 0xaa, 0xb7, 0xf5,
					0x76, 0xd6, 0xe7, 0xed, 0x90,
					0x69, 0x51, 0x3d, 0x9b, 0x3a,
					0x9d, 0xa8, 0xcf, 0xf9, 0x2f};
	unsigned char newsecret[20];
	int newsecsize = sizeof(newsecret);
	unsigned char newload[128];
	int newloadsize=sizeof(newload);

	rc = make_authobj(id, pass, nonce, secret, sizeof(secret),
			payload, strlen((char *)payload),
			authobj, &authsize);
	printf("make_authobj() rc=%d size=%d\n", rc, authsize);
	if (rc) return rc;

	rc = make_challenge(id, pass, nonce, challenge, &challengesize);
	printf("make_challenge() rc=%d size=%d\n", rc, challengesize);
	if (rc) return rc;

	rc = parse_authobj(key, sizeof(key), authobj, authsize,
			newsecret, &newsecsize, newload, &newloadsize);
	printf("parse_authobj() rc=%d secretsize=%d payload=\"%.*s\" (%d)\n",
		rc, newsecsize, newloadsize, newload, newloadsize);
	if (memcmp(secret, newsecret, newsecsize)) {
		printf("extracted secret does not match\n");
		return -1;
	}
	return 0;
}
