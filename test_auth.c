#include <stdio.h>
#include <string.h>
#include "authobj.h"
#include "crypto.h"

int main(int argc, char *argv[])
{
	const char *id = "testuser";
	const char *pass = "testpassword";
	const char *nonce = "1";
	const unsigned char secret[] = {0xb4, 0x62, 0xf2, 0x60, 0x87,
					0x78, 0x16, 0x87, 0xde, 0xce,
					0x80, 0x09, 0x24, 0x0b, 0x93,
					0xfc, 0xa0, 0xfc, 0x56, 0x56};
	const unsigned char *payload = (unsigned char *)
					"To authorize or not to authorize?";
	unsigned char authobj[128];
	int authsize = sizeof(authobj);
	unsigned char challenge[128];
	int challengesize = sizeof(challenge);
	int rc;
	unsigned char key[20];
	int keysize = sizeof(key);
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
	rc = hmac(secret, sizeof(secret), challenge, challengesize,
		&key, &keysize);
	printf("hmac(secret, challenge) rc=%d new_key_size=%d\n",
		rc, keysize);
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
